import type {
  SigningIntent,
  SignResult,
  HealthResponse,
  DIDResponse,
  Revocation,
  RevokeRequest
} from './types'

const BASE = '/api/v1'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'content-type': 'application/json' },
    ...init
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({ reason: res.statusText }))
    throw new Error(body.reason || `HTTP ${res.status}`)
  }

  return res.json()
}

export const api = {
  health: () => request<HealthResponse>('/health'),
  did: () => request<DIDResponse>('/did'),

  sign: (intent: SigningIntent) =>
    request<SignResult>('/sign', {
      method: 'POST',
      body: JSON.stringify(intent)
    }),

  listRevocations: () => request<{ revocations: Revocation[] }>('/revocations'),

  revoke: (req: RevokeRequest) =>
    request<{ status: string; did: string }>('/revoke', {
      method: 'POST',
      body: JSON.stringify(req)
    }),

  restore: (did: string) =>
    request<{ status: string; did: string }>('/restore', {
      method: 'POST',
      body: JSON.stringify({ did })
    }),

  metrics: async (): Promise<string> => {
    const res = await fetch('/metrics')
    return res.text()
  }
}
