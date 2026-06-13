import { describe, it, expect, beforeAll } from 'vitest'
import { signRequest, makePayload, revokeDID, waitForHealth } from './helpers.js'

describe('Revocation Flow', () => {
  beforeAll(async () => {
    await waitForHealth()
  }, 60_000)

  it('should reject sign when recipient DID is revoked', async () => {
    const revokedDID = 'did:peer:2.zEvictMePlease'

    // Revoke the DID
    await revokeDID(revokedDID)

    // Attempt to sign with the revoked recipient
    const { status, body } = await signRequest({
      action: 'a2a.message.sign',
      payload: {
        content: 'Message to revoked agent',
        content_type: 'text/plain',
        recipient_did: revokedDID,
      },
      agent_id: 'e2e-test-agent',
      timestamp: Math.floor(Date.now() / 1000),
      nonce: crypto.randomUUID(),
    })

    expect(status).toBe(403)
    expect(body.status).toBe('error')
    expect(body.reason).toBe('recipient_revoked')
  })

  it('should allow sign to non-revoked recipient', async () => {
    const { status, body } = await signRequest({
      action: 'a2a.message.sign',
      payload: {
        content: 'Message to valid agent',
        content_type: 'text/plain',
        recipient_did: 'did:peer:2.zValidAgent',
      },
      agent_id: 'e2e-test-agent',
      timestamp: Math.floor(Date.now() / 1000),
      nonce: crypto.randomUUID(),
    })

    expect(status).toBe(200)
    expect(body.status).toBe('signed')
  })
})
