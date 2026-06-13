import { describe, it, expect, vi, beforeEach } from 'vitest'
import { KeyGuardClient, KeyGuardError } from '../src/key-guard-client.js'
import { IntentBuilder, createIntent } from '../src/intent.js'
import type { SignResult, HealthResponse, DIDResponse } from '../src/types.js'

// ============================================================
// IntentBuilder
// ============================================================

describe('IntentBuilder', () => {
  it('creates an intent with default values', () => {
    const intent = new IntentBuilder('agent-alpha').build()

    expect(intent.agent_id).toBe('agent-alpha')
    expect(intent.action).toBe('a2a.message.sign')
    expect(intent.payload).toEqual({ content: '' })
    expect(intent.nonce).toBeDefined()
    expect(intent.nonce.length).toBeGreaterThanOrEqual(16)
    expect(intent.timestamp).toBeGreaterThan(0)
  })

  it('throws if agentId is empty', () => {
    expect(() => new IntentBuilder('')).toThrow('agentId is required')
    expect(() => new IntentBuilder('   ')).toThrow('agentId is required')
  })

  it('setAction changes the action', () => {
    const intent = new IntentBuilder('agent-alpha')
      .setAction('a2a.credential.issue')
      .build()

    expect(intent.action).toBe('a2a.credential.issue')
  })

  it('setPayload customizes payload', () => {
    const intent = new IntentBuilder('agent-alpha')
      .setPayload('Hello!', 'text/plain', 'did:peer:2.xyz')
      .build()

    expect(intent.payload.content).toBe('Hello!')
    expect(intent.payload.content_type).toBe('text/plain')
    expect(intent.payload.recipient_did).toBe('did:peer:2.xyz')
  })

  it('setNonce overrides the nonce', () => {
    const intent = new IntentBuilder('agent-alpha')
      .setNonce('custom-nonce-12345')
      .build()

    expect(intent.nonce).toBe('custom-nonce-12345')
  })

  it('setNonce throws if nonce < 16 chars', () => {
    expect(() => new IntentBuilder('agent-alpha').setNonce('short')).toThrow(
      'nonce must be at least 16 characters'
    )
  })

  it('createIntent is a shortcut for new IntentBuilder', () => {
    const builder = createIntent('agent-beta')
    expect(builder).toBeInstanceOf(IntentBuilder)
    expect(builder.build().agent_id).toBe('agent-beta')
  })

  it('fluent chaining works end-to-end', () => {
    const intent = new IntentBuilder('agent-gamma')
      .setAction('did.update')
      .setPayload('New DID doc', 'application/json', 'did:peer:2.abc')
      .setNonce('unique-nonce-12345678')
      .build()

    expect(intent.action).toBe('did.update')
    expect(intent.payload.content).toBe('New DID doc')
    expect(intent.nonce).toBe('unique-nonce-12345678')
  })
})

// ============================================================
// KeyGuardClient
// ============================================================

describe('KeyGuardClient', () => {
  const mockBaseURL = 'http://localhost:3099'

  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('strips trailing slash from baseURL', () => {
    const client = new KeyGuardClient({ baseURL: 'http://example.com/' })
    // @ts-expect-error access private field for testing
    expect(client.baseURL).toBe('http://example.com')
  })

  describe('sign — success', () => {
    it('returns SignResult on 200', async () => {
      const mockResponse: SignResult = {
        status: 'signed',
        request_id: 'req-123',
        did: 'did:peer:2.Ez6L...',
        envelope: {
          protected: 'base64',
          payload: 'base64',
          signature: 'base64',
        },
      }

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockResponse),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL })
      const result = await client.sign({
        action: 'a2a.message.sign',
        payload: { content: 'hello' },
        agent_id: 'alpha',
        timestamp: 1000,
        nonce: 'nonce-12345678901234',
      })

      expect(result.status).toBe('signed')
      expect(result.request_id).toBe('req-123')
      expect(result.envelope).toBeDefined()
    })
  })

  describe('sign — client errors (4xx)', () => {
    it('throws KeyGuardError on 400 with reason', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({
          status: 'invalid_schema',
          request_id: 'req-400',
          reason: 'Schema validation failed',
        }),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL })
      const err = await client.sign({
        action: 'a2a.message.sign',
        payload: { content: '' },
        agent_id: 'alpha',
        timestamp: 1000,
        nonce: 'nonce-12345678901234',
      }).catch(e => e)

      expect(err).toBeInstanceOf(KeyGuardError)
      expect(err.status).toBe(400)
      expect(err.message).toContain('Schema validation failed')
    })

    it('throws KeyGuardError on 403', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: () => Promise.resolve({
          status: 'recipient_revoked',
          request_id: 'req-403',
          reason: 'recipient credential revoked',
        }),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL })
      const err = await client.sign({
        action: 'a2a.message.sign',
        payload: { content: 'x', recipient_did: 'did:peer:2.bad' },
        agent_id: 'alpha',
        timestamp: 1000,
        nonce: 'nonce-12345678901234',
      }).catch(e => e)

      expect(err).toBeInstanceOf(KeyGuardError)
      expect(err.status).toBe(403)
    })

    it('throws KeyGuardError on 429 without retry', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: () => Promise.resolve({
          status: 'rate_limit_exceeded',
          request_id: 'req-429',
          reason: 'rate limit exceeded',
        }),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL })
      const err = await client.sign({
        action: 'a2a.message.sign',
        payload: { content: 'x' },
        agent_id: 'alpha',
        timestamp: 1000,
        nonce: 'nonce-12345678901234',
      }).catch(e => e)

      expect(err).toBeInstanceOf(KeyGuardError)
      expect(err.status).toBe(429)
      expect(globalThis.fetch).toHaveBeenCalledTimes(1) // no retry on 4xx
    })
  })

  describe('sign — retry on 5xx', () => {
    it('retries on 503 then succeeds', async () => {
      const mockResponse: SignResult = {
        status: 'signed',
        request_id: 'req-ok',
        did: 'did:peer:2.test',
      }

      const fetchSpy = vi.spyOn(globalThis, 'fetch')
      fetchSpy
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          json: () => Promise.resolve({ status: 'service_unavailable', request_id: 'req-503', reason: 'redis down' }),
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockResponse),
        } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL, maxRetries: 2 })
      const result = await client.sign({
        action: 'a2a.message.sign',
        payload: { content: 'x' },
        agent_id: 'alpha',
        timestamp: 1000,
        nonce: 'nonce-12345678901234',
      })

      expect(result.status).toBe('signed')
      expect(fetchSpy).toHaveBeenCalledTimes(2)
    })

    it('throws after exhausting retries', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
      fetchSpy.mockResolvedValue({
        ok: false,
        status: 503,
        json: () => Promise.resolve({ status: 'service_unavailable', request_id: 'req-503', reason: 'down' }),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL, maxRetries: 2 })
      const err = await client.sign({
        action: 'a2a.message.sign',
        payload: { content: 'x' },
        agent_id: 'alpha',
        timestamp: 1000,
        nonce: 'nonce-12345678901234',
      }).catch(e => e)

      expect(err).toBeInstanceOf(KeyGuardError)
      expect(err.status).toBe(503)
      expect(fetchSpy).toHaveBeenCalledTimes(2) // initial + 1 retry
    })
  })

  describe('health / getServiceDID', () => {
    it('returns health response', async () => {
      const mockHealth: HealthResponse = {
        status: 'ok',
        redis_connected: true,
        key_loaded: true,
        uptime_seconds: 42,
      }

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockHealth),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL })
      const result = await client.health()

      expect(result.status).toBe('ok')
      expect(result.redis_connected).toBe(true)
    })

    it('returns DID response', async () => {
      const mockDID: DIDResponse = {
        did: 'did:peer:2.Ez6L...',
        public_key_multibase: 'z6L...',
        key_type: 'Ed25519',
      }

      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockDID),
      } as Response)

      const client = new KeyGuardClient({ baseURL: mockBaseURL })
      const result = await client.getServiceDID()

      expect(result.did).toContain('did:peer:')
      expect(result.key_type).toBe('Ed25519')
    })
  })
})
