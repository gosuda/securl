package safebrowsing

import (
	"context"
	"testing"
	"time"
)

type lookupFunc func(context.Context, [][4]byte) (LookupResult, error)

func (lookup lookupFunc) Lookup(ctx context.Context, prefixes [][4]byte) (LookupResult, error) {
	return lookup(ctx, prefixes)
}

func TestCacheStoresPositiveAndNegativePrefixResults(t *testing.T) {
	calls := 0
	client := lookupFunc(func(_ context.Context, prefixes [][4]byte) (LookupResult, error) {
		calls++
		result := LookupResult{CacheSeconds: 60}
		for _, prefix := range prefixes {
			if prefix == [4]byte{1, 2, 3, 4} {
				var hash [32]byte
				copy(hash[:4], prefix[:])
				result.FullHashes = append(result.FullHashes, FullHash{
					Hash: hash, ThreatType: "MALWARE", Attributes: []string{"FRAME_ONLY"}, CacheSeconds: 60,
				})
			}
		}
		return result, nil
	})
	cache := NewCache(client, 8)
	now := time.Unix(8000, 0).UTC()
	cache.now = func() time.Time { return now }
	prefixes := [][4]byte{{1, 2, 3, 4}, {5, 6, 7, 8}}

	first, err := cache.Lookup(context.Background(), prefixes)
	if err != nil || calls != 1 || len(first.FullHashes) != 1 {
		t.Fatalf("first lookup: result=%+v calls=%d err=%v", first, calls, err)
	}
	first.FullHashes[0].Attributes[0] = "mutated"
	second, err := cache.Lookup(context.Background(), prefixes)
	if err != nil || calls != 1 || len(second.FullHashes) != 1 {
		t.Fatalf("cached lookup: result=%+v calls=%d err=%v", second, calls, err)
	}
	if second.FullHashes[0].Attributes[0] != "FRAME_ONLY" {
		t.Fatalf("cached result was mutated: %+v", second.FullHashes[0])
	}
}

func TestCacheExpiresAndEvictsLeastRecentlyUsedPrefix(t *testing.T) {
	calls := 0
	client := lookupFunc(func(_ context.Context, _ [][4]byte) (LookupResult, error) {
		calls++
		return LookupResult{CacheSeconds: 10}, nil
	})
	cache := NewCache(client, 1)
	now := time.Unix(9000, 0).UTC()
	cache.now = func() time.Time { return now }
	first := [][4]byte{{1, 1, 1, 1}}
	second := [][4]byte{{2, 2, 2, 2}}

	if _, err := cache.Lookup(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Lookup(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Lookup(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("LRU calls=%d", calls)
	}

	now = now.Add(11 * time.Second)
	if _, err := cache.Lookup(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("expiry calls=%d", calls)
	}
}

func TestCacheRejectsProviderHashesOutsideRequestedPrefixes(t *testing.T) {
	client := lookupFunc(func(_ context.Context, _ [][4]byte) (LookupResult, error) {
		var hash [32]byte
		copy(hash[:4], []byte{9, 9, 9, 9})
		return LookupResult{
			FullHashes:   []FullHash{{Hash: hash, ThreatType: "MALWARE"}},
			CacheSeconds: 60,
		}, nil
	})
	cache := NewCache(client, 8)
	if _, err := cache.Lookup(context.Background(), [][4]byte{{1, 2, 3, 4}}); err != ErrDependencyUnavailable {
		t.Fatalf("mismatched hash error=%v", err)
	}
}
