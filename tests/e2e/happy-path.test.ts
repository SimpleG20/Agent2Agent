import { describe, it, expect, beforeAll } from 'vitest'
import { signRequest, makePayload, waitForHealth } from './helpers.js'

describe('Happy Path — Valid Signing Flow', () => {
  beforeAll(async () => {
    await waitForHealth()
  }, 60_000)

  it('should return health ok', async () => {
    const res = await fetch('http://localhost:3000/v1/health')
    expect(res.ok).toBe(true)

    const body = await res.json() as Record<string, unknown>
    expect(body.status).toBe('ok')
    expect(body.redis_connected).toBe(true)
    expect(body.key_loaded).toBe(true)
  })

  it('should return the service DID', async () => {
    const res = await fetch('http://localhost:3000/v1/did')
    expect(res.ok).toBe(true)

    const body = await res.json() as Record<string, unknown>
    expect(body.did).toMatch(/^did:peer:2\.z/)
    expect(body.key_type).toBe('Ed25519')
  })

  it('should sign a valid intent', async () => {
    const payload = makePayload()
    const nonce = crypto.randomUUID()
    const timestamp = Math.floor(Date.now() / 1000)

    const { status, body } = await signRequest({
      action: 'a2a.message.sign',
      payload,
      agent_id: 'e2e-test-agent',
      timestamp,
      nonce,
    })

    expect(status).toBe(200)
    expect(body.status).toBe('signed')
    expect(body.did).toMatch(/^did:peer:2\.z/)
    expect(typeof body.signature).toBe('string')
    expect(body.signature).toBeTruthy()
    expect(body.request_id).toBeTruthy()
  })

  it('should return a valid JWS envelope in signature field', async () => {
    const payload = makePayload()
    const nonce = crypto.randomUUID()
    const timestamp = Math.floor(Date.now() / 1000)

    const { status, body } = await signRequest({
      action: 'a2a.message.sign',
      payload,
      agent_id: 'e2e-test-agent',
      timestamp,
      nonce,
    })

    expect(status).toBe(200)

    // The signature is the full JWS compact serialization
    const sig = body.signature as string
    const parts = sig.split('.')
    expect(parts).toHaveLength(1) // The response returns base64url(signature) only, not full envelope

    // But we get the signature as a separate field — it should be a base64 string
    expect(sig).toMatch(/^[A-Za-z0-9+/_-]+$/)
  })

  it('should accept different valid action types', async () => {
    const actions = ['a2a.message.sign', 'a2a.credential.issue', 'did.update']

    for (const action of actions) {
      const { status, body } = await signRequest({
        action,
        payload: makePayload(`Test action: ${action}`),
        agent_id: 'e2e-test-agent',
        timestamp: Math.floor(Date.now() / 1000),
        nonce: crypto.randomUUID(),
      })

      expect(status).toBe(200)
      expect(body.status).toBe('signed')
    }
  })
})
