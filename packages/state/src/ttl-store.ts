const DEFAULT_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours
const DEFAULT_SWEEP_INTERVAL_MS = 60 * 1000; // 60 seconds

interface Entry<T> {
  value: T;
  expiresAt: number;
}

export class TTLStore<T> {
  private readonly store = new Map<string, Entry<T>>();
  private sweepTimer: ReturnType<typeof setInterval> | null = null;
  private readonly defaultTtlMs: number;

  constructor(
    defaultTtlMs: number = DEFAULT_TTL_MS,
    sweepIntervalMs: number = DEFAULT_SWEEP_INTERVAL_MS,
  ) {
    this.defaultTtlMs = defaultTtlMs;
    this.sweepTimer = setInterval(() => this.sweep(), sweepIntervalMs);
    // Allow the process to exit even if the timer is running
    if (this.sweepTimer && typeof this.sweepTimer === "object" && "unref" in this.sweepTimer) {
      this.sweepTimer.unref();
    }
  }

  set(key: string, value: T, ttlMs?: number): void {
    const ttl = ttlMs ?? this.defaultTtlMs;
    this.store.set(key, {
      value,
      expiresAt: Date.now() + ttl,
    });
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;

    if (Date.now() >= entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }

    return entry.value;
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  get size(): number {
    this.sweep();
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  destroy(): void {
    if (this.sweepTimer !== null) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
    this.store.clear();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now >= entry.expiresAt) {
        this.store.delete(key);
      }
    }
  }
}
