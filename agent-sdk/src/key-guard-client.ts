import type {
  SigningIntent,
  SignResult,
  HealthResponse,
  DIDResponse,
  KeyGuardClientOptions,
} from './types.js'

const DEFAULT_TIMEOUT = 5_000
const MAX_RETRIES = 3
const BASE_DELAY_MS = 100

/** Error thrown by KeyGuardClient */
export class KeyGuardError extends Error {
  status: number
  requestId: string

  constructor(message: string, status: number, requestId: string) {
    super(message)
    this.name = 'KeyGuardError'
    this.status = status
    this.requestId = requestId
  }
}

/** HTTP client for Key Guard service with retry + exponential backoff */
export class KeyGuardClient {
  private baseURL: string
  private timeout: number
  private maxRetries: number

  constructor(options: KeyGuardClientOptions) {
    // Strip trailing slash
    this.baseURL = options.baseURL.replace(/\/+$/, '')
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT
    this.maxRetries = options.maxRetries ?? MAX_RETRIES
  }

  /** Sign an intent — retries on 5xx only */
  async sign(intent: SigningIntent): Promise<SignResult> {
    return this.requestWithRetry<SignResult>('/v1/sign', {
      method: 'POST',
      body: JSON.stringify(intent),
    })
  }

  /** Health check */
  async health(): Promise<HealthResponse> {
    return this.requestWithRetry<HealthResponse>('/v1/health', {
      method: 'GET',
    })
  }

  /** Get the service's public DID */
  async getServiceDID(): Promise<DIDResponse> {
    return this.requestWithRetry<DIDResponse>('/v1/did', {
      method: 'GET',
    })
  }

  /** Perform a request with retry + exponential backoff for 5xx errors */
  private async requestWithRetry<T>(
    path: string,
    init: RequestInit,
    attempt: number = 1
  ): Promise<T> {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), this.timeout)

      const response = await fetch(`${this.baseURL}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...init.headers,
        },
      })

      clearTimeout(timeoutId)

      // Parse response body
      const body: any = await response.json()

      // 4xx — don't retry (client error)
      if (response.status >= 400 && response.status < 500) {
        throw new KeyGuardError(
          body.reason ?? body.status ?? 'Request rejected',
          response.status,
          body.request_id ?? 'unknown'
        )
      }

      // 5xx — retry if attempts remain
      if (response.status >= 500) {
        return this.retryOrThrow<T>(path, init, attempt, response.status, body)
      }

      return body as T
    } catch (err) {
      if (err instanceof KeyGuardError) throw err

      // Network or timeout — retry if attempts remain
      if (attempt < this.maxRetries) {
        await this.delay(attempt)
        return this.requestWithRetry<T>(path, init, attempt + 1)
      }

      throw new KeyGuardError(
        err instanceof Error ? err.message : 'Request failed',
        503,
        'unknown'
      )
    }
  }

  /** Handle 5xx responses with retry */
  private async retryOrThrow<T>(
    path: string,
    init: RequestInit,
    attempt: number,
    status: number,
    body: any
  ): Promise<T> {
    if (attempt >= this.maxRetries) {
      throw new KeyGuardError(
        body.reason ?? body.status ?? 'Server error',
        status,
        body.request_id ?? 'unknown'
      )
    }

    await this.delay(attempt)
    return this.requestWithRetry<T>(path, init, attempt + 1)
  }

  /** Exponential backoff: 100ms, 300ms, 900ms */
  private async delay(attempt: number): Promise<void> {
    const ms = BASE_DELAY_MS * Math.pow(3, attempt - 1)
    await new Promise(resolve => setTimeout(resolve, ms))
  }
}
