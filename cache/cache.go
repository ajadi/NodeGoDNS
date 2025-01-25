package cache

import (
    "time"

    "github.com/patrickmn/go-cache"
)

// DNSCache wraps go-cache for DNS caching.
type DNSCache struct {
    c *cache.Cache
}

// NewDNSCache creates a DNSCache with default expiration and cleanup.
func NewDNSCache(defaultExpiration, cleanupInterval time.Duration) *DNSCache {
    return &DNSCache{
        c: cache.New(defaultExpiration, cleanupInterval),
    }
}

// Get retrieves an item by key from the cache.
func (d *DNSCache) Get(key string) (interface{}, bool) {
    return d.c.Get(key)
}

// Set stores an item in the cache with an expiration.
func (d *DNSCache) Set(key string, value interface{}, expiration time.Duration) {
    d.c.Set(key, value, expiration)
}

// Delete removes an item from the cache.
func (d *DNSCache) Delete(key string) {
    d.c.Delete(key)
}

// Flush clears the entire cache.
func (d *DNSCache) Flush() {
    d.c.Flush()
}
