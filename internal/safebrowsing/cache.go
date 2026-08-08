package safebrowsing

import (
	"container/list"
	"context"
	"sync"
	"time"
)

const DefaultCacheEntries = 4096

type cacheEntry struct {
	prefix     [4]byte
	fullHashes []FullHash
	expiresAt  time.Time
}

type Cache struct {
	client     LookupClient
	maxEntries int
	mu         sync.Mutex
	entries    map[[4]byte]*list.Element
	lru        *list.List
	now        func() time.Time
}

func NewCache(client LookupClient, maxEntries int) *Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheEntries
	}
	return &Cache{
		client:     client,
		maxEntries: maxEntries,
		entries:    make(map[[4]byte]*list.Element),
		lru:        list.New(),
		now:        time.Now,
	}
}

func cloneFullHashes(fullHashes []FullHash) []FullHash {
	cloned := make([]FullHash, len(fullHashes))
	copy(cloned, fullHashes)
	for index := range cloned {
		cloned[index].Attributes = append([]string(nil), fullHashes[index].Attributes...)
	}
	return cloned
}

func remainingCacheSeconds(now, expiresAt time.Time) uint32 {
	if !now.Before(expiresAt) {
		return 0
	}
	seconds := uint64(expiresAt.Sub(now) / time.Second)
	if seconds > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(seconds)
}

func (cache *Cache) get(prefix [4]byte, now time.Time) ([]FullHash, uint32, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element, ok := cache.entries[prefix]
	if !ok {
		return nil, 0, false
	}
	entry := element.Value.(*cacheEntry)
	if !now.Before(entry.expiresAt) {
		cache.lru.Remove(element)
		delete(cache.entries, prefix)
		return nil, 0, false
	}
	cache.lru.MoveToFront(element)
	seconds := remainingCacheSeconds(now, entry.expiresAt)
	fullHashes := cloneFullHashes(entry.fullHashes)
	for index := range fullHashes {
		fullHashes[index].CacheSeconds = seconds
	}
	return fullHashes, seconds, true
}

func (cache *Cache) put(prefix [4]byte, fullHashes []FullHash, expiresAt time.Time) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if existing, ok := cache.entries[prefix]; ok {
		existing.Value = &cacheEntry{
			prefix: prefix, fullHashes: cloneFullHashes(fullHashes), expiresAt: expiresAt,
		}
		cache.lru.MoveToFront(existing)
	} else {
		element := cache.lru.PushFront(&cacheEntry{
			prefix: prefix, fullHashes: cloneFullHashes(fullHashes), expiresAt: expiresAt,
		})
		cache.entries[prefix] = element
	}
	for cache.lru.Len() > cache.maxEntries {
		oldest := cache.lru.Back()
		entry := oldest.Value.(*cacheEntry)
		delete(cache.entries, entry.prefix)
		cache.lru.Remove(oldest)
	}
}

func (cache *Cache) Lookup(ctx context.Context, prefixes [][4]byte) (LookupResult, error) {
	unique, err := deduplicatePrefixes(prefixes)
	if err != nil {
		return LookupResult{}, err
	}
	now := cache.now().UTC()
	result := LookupResult{}
	missing := make([][4]byte, 0, len(unique))
	minimumCacheSeconds := ^uint32(0)
	for _, prefix := range unique {
		fullHashes, cacheSeconds, ok := cache.get(prefix, now)
		if !ok {
			missing = append(missing, prefix)
			continue
		}
		result.FullHashes = append(result.FullHashes, fullHashes...)
		if cacheSeconds < minimumCacheSeconds {
			minimumCacheSeconds = cacheSeconds
		}
	}

	if len(missing) > 0 {
		fetched, err := cache.client.Lookup(ctx, missing)
		if err != nil {
			return LookupResult{}, err
		}
		missingSet := make(map[[4]byte]struct{}, len(missing))
		matches := make(map[[4]byte][]FullHash, len(missing))
		for _, prefix := range missing {
			missingSet[prefix] = struct{}{}
		}
		for _, fullHash := range fetched.FullHashes {
			prefix := [4]byte(fullHash.Hash[:4])
			if _, ok := missingSet[prefix]; !ok {
				return LookupResult{}, ErrDependencyUnavailable
			}
			matches[prefix] = append(matches[prefix], fullHash)
		}
		expiresAt := now.Add(time.Duration(fetched.CacheSeconds) * time.Second)
		for _, prefix := range missing {
			cache.put(prefix, matches[prefix], expiresAt)
		}
		result.FullHashes = append(result.FullHashes, cloneFullHashes(fetched.FullHashes)...)
		if fetched.CacheSeconds < minimumCacheSeconds {
			minimumCacheSeconds = fetched.CacheSeconds
		}
	}
	if minimumCacheSeconds != ^uint32(0) {
		result.CacheSeconds = minimumCacheSeconds
	}
	return result, nil
}
