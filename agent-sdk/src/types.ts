/** Types for A2A Key Guard Agent SDK */

/** Intent to be signed by Key Guard */
export interface SigningIntent {
  action: 'a2a.message.sign' | 'a2a.credential.issue' | 'did.update'
  payload: {
    content: string
    content_type?: string
    recipient_did?: string
  }
  agent_id: string
  timestamp: number
  nonce: string
}

/** DIDComm JWS envelope returned by Key Guard */
export interface JWSEnvelope {
  protected: string
  payload: string
  signature: string
}

/** Result of a sign request */
export interface SignResult {
  status: 'signed' | 'rejected'
  request_id: string
  did?: string
  envelope?: JWSEnvelope
  reason?: string
}

/** Health check response */
export interface HealthResponse {
  status: string
  redis_connected: boolean
  key_loaded: boolean
  uptime_seconds: number
}

/** DID info response */
export interface DIDResponse {
  did: string
  public_key_multibase: string
  key_type: string
}

/** Error response from Key Guard */
export interface ErrorResponse {
  status: string
  request_id: string
  reason: string
}

/** Options for KeyGuardClient */
export interface KeyGuardClientOptions {
  baseURL: string
  timeout?: number
  maxRetries?: number
}
