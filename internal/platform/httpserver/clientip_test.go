package httpserver

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, cidr string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", cidr, err)
	}
	return p
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{
		mustPrefix(t, "10.0.0.0/8"),
		mustPrefix(t, "172.16.0.0/12"),
		mustPrefix(t, "fd00::/8"),
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        []string
		trusted    []netip.Prefix
		want       string
	}{
		{
			name:       "direct client forging XFF with empty trusted proxies is ignored",
			remoteAddr: "198.51.100.42:54321",
			xff:        []string{"203.0.113.1"},
			trusted:    nil,
			want:       "198.51.100.42",
		},
		{
			name:       "direct untrusted client forging XFF is ignored",
			remoteAddr: "198.51.100.42:54321",
			xff:        []string{"203.0.113.1"},
			trusted:    trusted,
			want:       "198.51.100.42",
		},
		{
			name:       "single trusted proxy returns client IP",
			remoteAddr: "10.0.0.5:443",
			xff:        []string{"198.51.100.77"},
			trusted:    trusted,
			want:       "198.51.100.77",
		},
		{
			name:       "multi-proxy chain ignores client-forged leftmost IP",
			remoteAddr: "10.0.0.5:443",
			xff:        []string{"1.2.3.4, 198.51.100.77, 172.16.0.10"},
			trusted:    trusted,
			want:       "198.51.100.77",
		},
		{
			name:       "multiple XFF headers concatenated right-to-left",
			remoteAddr: "10.0.0.5:443",
			xff:        []string{"1.2.3.4, 198.51.100.88", "172.16.0.10"},
			trusted:    trusted,
			want:       "198.51.100.88",
		},
		{
			name:       "IPv6 client behind IPv6 trusted proxy",
			remoteAddr: "[fd00::1]:12345",
			xff:        []string{"2001:db8::99, fd00::2"},
			trusted:    trusted,
			want:       "2001:db8::99",
		},
		{
			name:       "invalid XFF value falls back safely",
			remoteAddr: "10.0.0.5:443",
			xff:        []string{"not-an-ip"},
			trusted:    trusted,
			want:       "10.0.0.5",
		},
		{
			name:       "invalid hop after trusted hop stops scanning left",
			remoteAddr: "10.0.0.5:443",
			xff:        []string{"198.51.100.1, garbage, 172.16.0.10"},
			trusted:    trusted,
			want:       "172.16.0.10",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			if got := ClientIP(req, tc.trusted); got != tc.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
