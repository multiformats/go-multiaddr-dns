package madns

import (
	"context"
	"testing"
	"time"
)

// mockTTLResolver is a MockResolver that also reports a fixed TTL for TXT lookups.
type mockTTLResolver struct {
	*MockResolver
	ttl time.Duration
}

func (r *mockTTLResolver) LookupTXTWithTTL(ctx context.Context, name string) ([]string, time.Duration, error) {
	txt, err := r.MockResolver.LookupTXT(ctx, name)
	return txt, r.ttl, err
}

func TestLookupTXTWithTTL(t *testing.T) {
	ctx := context.Background()

	def := &MockResolver{TXT: map[string][]string{
		"example.com": {"dnslink=/ipfs/bafkqaaa"},
	}}
	withTTL := &mockTTLResolver{
		MockResolver: &MockResolver{TXT: map[string][]string{
			"custom.test": {"dnslink=/ipfs/bafkqaaa"},
		}},
		ttl: 42 * time.Second,
	}

	rslv, err := NewResolver(
		WithDefaultResolver(def),
		WithDomainResolver("custom.test", withTTL),
	)
	if err != nil {
		t.Fatal(err)
	}

	// the matched per-domain resolver supports TTL, so it is reported
	txt, ttl, err := rslv.LookupTXTWithTTL(ctx, "custom.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(txt) != 1 {
		t.Fatalf("expected 1 TXT record, got %d", len(txt))
	}
	if ttl != 42*time.Second {
		t.Fatalf("expected ttl 42s, got %s", ttl)
	}

	// the default resolver does not support TTL, so it is reported as unknown (0)
	_, ttl, err = rslv.LookupTXTWithTTL(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 0 {
		t.Fatalf("expected unknown ttl 0 for resolver without TTL support, got %s", ttl)
	}
}
