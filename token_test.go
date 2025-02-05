package identity

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

// mockIdentity implements the Identity interface for testing
type mockIdentity struct {
	serverCerts []*tls.Certificate
	clientCert  *tls.Certificate
}

func (m *mockIdentity) Cert() *tls.Certificate         { return m.clientCert }
func (m *mockIdentity) ServerCert() []*tls.Certificate { return m.serverCerts }
func (m *mockIdentity) CA() *x509.CertPool             { return nil }
func (m *mockIdentity) CaPool() *CaPool                { return nil }
func (m *mockIdentity) ServerTLSConfig() *tls.Config   { return nil }
func (m *mockIdentity) ClientTLSConfig() *tls.Config   { return nil }
func (m *mockIdentity) Reload() error                  { return nil }
func (m *mockIdentity) WatchFiles() error              { return nil }
func (m *mockIdentity) StopWatchingFiles()             {}
func (m *mockIdentity) SetCert(_ string) error         { return nil }
func (m *mockIdentity) SetServerCert(_ string) error   { return nil }
func (m *mockIdentity) GetConfig() *Config             { return nil }
func (m *mockIdentity) ValidFor(_ string) error        { return nil }

const (
	validDNS       = "example.com"
	invalidDNS     = "invalid.com"
	validIP4       = "192.168.1.1"
	invalidIP4     = "10.0.0.1"
	validIP6       = "::1"
	invalidIP6     = "fe80::1"
	validPort      = "443"
	expandedIPv6   = "2001:0db8:0000:0000:0000:ff00:0042:8329"
	compressedIPv6 = "2001:0db8::ff00:0042:8329"
)

// Helper to create a mock identity with certs
func createMockIdentity(dnsNames []string, ipAddresses []string) *TokenId {
	leaf := &x509.Certificate{}
	for _, dns := range dnsNames {
		leaf.DNSNames = append(leaf.DNSNames, dns)
	}
	for _, ip := range ipAddresses {
		leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(ip))
	}

	tlsCert := &tls.Certificate{Leaf: leaf}
	mi := &mockIdentity{
		serverCerts: []*tls.Certificate{tlsCert},
		clientCert:  tlsCert,
	}
	id := &TokenId{
		Identity: mi,
		Token:    "",
		Data:     nil,
	}
	return id
}

func TestValidFor_ValidHostname(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{})

	err := id.ValidFor(validDNS + "aa:" + validPort)
	if err != nil {
		t.Errorf("Expected valid hostname, got error: %v", err)
	}
}

func TestValidFor_InvalidHostname(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{})

	err := id.ValidFor(invalidDNS + ":" + validPort)
	if err == nil {
		t.Fatalf("Expected error for invalid hostname, got nil")
	}
	require.Equal(t, "identity is not valid for provided host: ["+invalidDNS+"]. is valid for: ["+validDNS+"]", err.Error())
}

func TestValidFor_ValidIPv4(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP4})

	err := id.ValidFor(validIP4 + ":" + validPort)
	if err != nil {
		t.Errorf("Expected valid IP, got error: %v", err)
	}
}

func TestValidFor_InvalidIPv4(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP4})

	err := id.ValidFor(invalidIP4 + ":" + validPort)
	if err == nil {
		t.Fatalf("Expected error for invalid IP, got nil")
	}
	require.Equal(t, "identity is not valid for provided host: ["+invalidIP4+"]. is valid for: ["+validIP4+"]", err.Error())
}

func TestValidFor_ValidIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP6})

	err := id.ValidFor("[" + validIP6 + "]:" + validPort)
	if err != nil {
		t.Errorf("Expected valid IPv6, got error: %v", err)
	}
}

func TestValidFor_InvalidIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP6})

	err := id.ValidFor("[" + invalidIP6 + "]:" + validPort)
	if err == nil {
		t.Fatalf("Expected error for invalid IPv6, got nil")
	}
	require.Equal(t, "identity is not valid for provided host: ["+invalidIP6+"]. is valid for: ["+validIP6+"]", err.Error())
}

func TestValidFor_ValidMixed(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{validIP4})

	err1 := id.ValidFor(validDNS + ":" + validPort)
	err2 := id.ValidFor(validIP4 + ":" + validPort)

	if err1 != nil {
		t.Fatalf("Expected valid hostname, got error: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("Expected valid IP, got error: %v", err2)
	}
}

func TestValidFor_InvalidMixed(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{validIP4})

	err1 := id.ValidFor(invalidDNS + ":" + validPort)
	err2 := id.ValidFor(invalidIP4 + ":" + validPort)

	if err1 == nil {
		t.Fatalf("Expected error for invalid hostname, got nil")
	}
	require.Equal(t, "identity is not valid for provided host: ["+invalidDNS+"]. is valid for: ["+validIP4+", "+validDNS+"]", err1.Error())
	if err2 == nil {
		t.Fatalf("Expected error for invalid IP, got nil")
	}
	require.Equal(t, "identity is not valid for provided host: ["+invalidIP4+"]. is valid for: ["+validIP4+", "+validDNS+"]", err2.Error())
}

func TestValidFor_NoCerts(t *testing.T) {
	id := createMockIdentity([]string{}, []string{})

	err := id.ValidFor(validDNS + ":" + validPort)
	if err == nil {
		t.Fatalf("Expected error for no valid certs, got nil")
	}
	require.Equal(t, "identity is not valid for provided host: ["+validDNS+"]. is valid for: []", err.Error())
}

func TestValidFor_ExpandedIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{expandedIPv6})

	err := id.ValidFor("[" + expandedIPv6 + "]:" + validPort)
	if err != nil {
		t.Errorf("Expected valid hostname, got error: %v", err)
	}
}

func TestValidFor_CompressedIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{compressedIPv6})

	err := id.ValidFor("[" + compressedIPv6 + "]:" + validPort)
	if err != nil {
		t.Errorf("Expected valid hostname, got error: %v", err)
	}
}

func TestValidFor_ExpandedIPv6_MatchesCompressed(t *testing.T) {
	id := createMockIdentity([]string{}, []string{expandedIPv6})

	err := id.ValidFor("[" + compressedIPv6 + "]:" + validPort)
	if err != nil {
		t.Errorf("Expected valid hostname, got error: %v", err)
	}
}

func TestValidFor_CompressedIPv6_MatchesExpanded(t *testing.T) {
	id := createMockIdentity([]string{}, []string{compressedIPv6})

	err := id.ValidFor("[" + expandedIPv6 + "]:" + validPort)
	if err != nil {
		t.Errorf("Expected valid hostname, got error: %v", err)
	}
}
