/** Wrapper for HTTP response with parsed body */
export interface ServerResponse {
  status: number
  body: Record<string, unknown>
}

/** Expected sign request fields */
export interface SignRequest {
  action: string
  payload: Record<string, unknown>
  agent_id: string
  timestamp: number
  nonce: string
}
