package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/server/middleware"
)

type Config struct {
	HeaderDepths map[string]int    `json:"headerDepths,omitempty"` // Maps headers to their corresponding depth
	SourceRanges map[string][]string `json:"sourceRanges,omitempty"` // Maps headers to their corresponding IP whitelist
}

func CreateConfig() *Config {
	return &Config{
		HeaderDepths: make(map[string]int),
		SourceRanges: make(map[string][]string),
	}
}

type MultiDepthIPWhitelist struct {
	next         http.Handler
	name         string
	headerDepths map[string]int
	sourceRanges map[string][]string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.SourceRanges) == 0 {
		return nil, fmt.Errorf("sourceRanges is required")
	}

	return &MultiDepthIPWhitelist{
		next:         next,
		name:         name,
		headerDepths: config.HeaderDepths,
		sourceRanges: config.SourceRanges,
	}, nil
}

func (m *MultiDepthIPWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for header, depth := range m.headerDepths {
		ip := m.getIP(req, header, depth)

		if ip != "" && m.isAllowed(ip, m.sourceRanges[header]) {
			m.next.ServeHTTP(rw, req)
			return
		}
	}

	// Fallback to checking the source IP directly
	if m.isAllowed(req.RemoteAddr, m.sourceRanges["source"]) {
		m.next.ServeHTTP(rw, req)
		return
	}

	http.Error(rw, "Forbidden", http.StatusForbidden)
}

func (m *MultiDepthIPWhitelist) getIP(req *http.Request, header string, depth int) string {
	if header == "source" {
		return req.RemoteAddr
	}

	headerValue := req.Header.Get(header)
	if headerValue != "" {
		ips := strings.Split(headerValue, ",")
		if depth > 0 && depth <= len(ips) {
			return strings.TrimSpace(ips[depth-1])
		}
	}
	return ""
}

func (m *MultiDepthIPWhitelist) isAllowed(ip string, allowedRanges []string) bool {
	for _, cidr := range allowedRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		CreateConfig: CreateConfig,
		New:          New,
	})
}
