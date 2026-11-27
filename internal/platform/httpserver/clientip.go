package httpserver

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the real client IP address for rate limiting, audit logs,
// and session ip_prefix (CTO #21). If r.RemoteAddr is not inside trustedProxies
// (or trustedProxies is empty), X-Forwarded-For is ignored to prevent spoofing.
// When r.RemoteAddr is a trusted proxy, X-Forwarded-For is scanned from right
// to left and the first valid address outside trustedProxies is returned.
func ClientIP(r *http.Request, trustedProxies []netip.Prefix) string {
	remoteIP, ok := parseRemoteAddr(r.RemoteAddr)
	if !ok {
		if addr := strings.TrimSpace(r.RemoteAddr); addr != "" {
			return addr
		}
		return "unknown"
	}

	if len(trustedProxies) == 0 || !isTrustedIP(remoteIP, trustedProxies) {
		return remoteIP.String()
	}

	xffHeaders := r.Header.Values("X-Forwarded-For")
	if len(xffHeaders) == 0 {
		return remoteIP.String()
	}

	var hops []string
	for _, hdr := range xffHeaders {
		for _, part := range strings.Split(hdr, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				hops = append(hops, trimmed)
			}
		}
	}
	if len(hops) == 0 {
		return remoteIP.String()
	}

	lastValid := remoteIP
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			// Stop trusting further left entries once an invalid hop is encountered.
			return lastValid.String()
		}
		addr = addr.Unmap()
		lastValid = addr
		if !isTrustedIP(addr, trustedProxies) {
			return addr.String()
		}
	}

	return lastValid.String()
}

func parseRemoteAddr(remoteAddr string) (netip.Addr, bool) {
	raw := strings.TrimSpace(remoteAddr)
	if raw == "" {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func isTrustedIP(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
