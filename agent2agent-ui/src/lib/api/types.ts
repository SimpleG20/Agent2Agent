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

export interface JWSEnvelope {
  protected: string
  payload: string
  signature: string
}

export interface SignResult {
  status: 'signed' | 'rejected'
  request_id: string
  did?: string
  envelope?: JWSEnvelope
  reason?: string
}

export interface HealthResponse {
  status: string
  redis_connected: boolean
  key_loaded: boolean
  uptime_seconds: number
}

export interface DIDResponse {
  did: string
  public_key_multibase: string
  key_type: string
}

export interface Revocation {
  did: string
  status: 'revoked' | 'suspended'
  ttl_seconds: number
  reason?: string
}

export interface RevokeRequest {
  did: string
  status?: 'revoked' | 'suspended'
  ttl_seconds?: number
  reason?: string
}

export interface ApiError {
  status: 'error'
  reason: string
  request_id?: string
}
