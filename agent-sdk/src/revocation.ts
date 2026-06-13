import Redis from 'ioredis'

/** Cache entry with expiration */
interface CacheEntry {
  revoked: boolean
  timestamp: number
}

/** Check if a DID has been revoked via Redis */
export class RevocationChecker {
  private redis: Redis
  private cache: Map<string, CacheEntry> = new Map()
  private cacheTTLMs: number

  constructor(
    redisURL: string,
    options?: { cacheTTLMs?: number }
  ) {
    this.redis = new Redis(redisURL, {
      enableOfflineQueue: false,
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      retryStrategy: () => null, // disable auto-retry
    })
    this.cacheTTLMs = options?.cacheTTLMs ?? 10_000
  }

  /** Check if a DID is revoked (with 10s cache) */
  async isRevoked(did: string): Promise<boolean> {
    const cached = this.cache.get(did)
    const now = Date.now()

    if (cached && (now - cached.timestamp) < this.cacheTTLMs) {
      return cached.revoked
    }

    try {
      const value = await this.redis.get(`revocation:${did}`)
      const revoked = value === 'revoked' || value === 'suspended'

      this.cache.set(did, { revoked, timestamp: now })
      return revoked
    } catch {
      // Redis unavailable — fail open for revocation check (read-only)
      // The Key Guard itself fails closed on sign, but the agent
      // should still be able to process messages in degraded mode
      return false
    }
  }

  /** Clear cached revocation status for a DID */
  clearCache(did: string): void {
    this.cache.delete(did)
  }

  /** Clear entire cache */
  clearAllCache(): void {
    this.cache.clear()
  }

  /** Disconnect from Redis */
  async disconnect(): Promise<void> {
    await this.redis.quit()
    this.cache.clear()
  }
}
