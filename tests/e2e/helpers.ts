import type { ServerResponse } from './types.js'

const KEY_GUARD_URL = process.env.KEY_GUARD_URL ?? 'http://localhost:3000'

/** Default signing intent payload */
export function makePayload(content?: string): { content: string; content_type: string } {
  return {
    content: content ?? 'Hello from E2E test agent!',
    content_type: 'text/plain',
  }
}

/** Send a POST /v1/sign request */
export async function signRequest(body: Record<string, unknown>): Promise<ServerResponse> {
  const res = await fetch(`${KEY_GUARD_URL}/v1/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  return { status: res.status, body: data }
}

/** Wait for the Key Guard health endpoint to return ok */
export async function waitForHealth(
  maxRetries = 30,
  delayMs = 1000
): Promise<void> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await fetch(`${KEY_GUARD_URL}/v1/health`)
      if (res.ok) return
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, delayMs))
  }
  throw new Error('Key Guard did not become healthy')
}

/** Set a revocation key in Redis via the Key Guard's Redis */
export async function revokeDID(did: string): Promise<void> {
  // We use the Redis port directly from the test host
  const redisURL = process.env.E2E_REDIS_URL ?? 'redis://localhost:6379'

  // Dynamic import of ioredis (dev dependency in e2e package)
  const { default: Redis } = await import('ioredis')
  const redis = new Redis(redisURL, {
    maxRetriesPerRequest: 1,
    retryStrategy: () => null,
  })

  try {
    await redis.set(`revocation:${did}`, 'revoked', 'EX', 60)
  } finally {
    await redis.quit()
  }
}
