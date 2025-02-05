package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	leaf.DNSNames = append(leaf.DNSNames, dnsNames...)
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

	err := id.ValidFor(validDNS + ":" + validPort)
	require.NoError(t, err)
}

func TestValidFor_InvalidHostname(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{})

	err := id.ValidFor(invalidDNS + ":" + validPort)
	require.True(t, errors.Is(err, ErrInvalidAddressForIdentity))
	var addrErr *AddressError
	if errors.As(err, &addrErr) {
		require.Equal(t, addrErr.Host, invalidDNS)
		require.Contains(t, addrErr.ValidFor, validDNS)
	}
}

func TestValidFor_ValidIPv4(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP4})

	err := id.ValidFor(validIP4 + ":" + validPort)
	require.NoError(t, err)
}

func TestValidFor_InvalidIPv4(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP4})

	err := id.ValidFor(invalidIP4 + ":" + validPort)
	require.True(t, errors.Is(err, ErrInvalidAddressForIdentity))
	var addrErr *AddressError
	if errors.As(err, &addrErr) {
		require.Equal(t, addrErr.Host, invalidIP4)
		require.Contains(t, addrErr.ValidFor, validIP4)
	}
}

func TestValidFor_ValidIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP6})

	err := id.ValidFor("[" + validIP6 + "]:" + validPort)
	require.NoError(t, err)
}

func TestValidFor_InvalidIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{validIP6})

	err := id.ValidFor("[" + invalidIP6 + "]:" + validPort)
	require.True(t, errors.Is(err, ErrInvalidAddressForIdentity))
	var addrErr *AddressError
	if errors.As(err, &addrErr) {
		require.Equal(t, addrErr.Host, invalidIP6)
		require.Contains(t, addrErr.ValidFor, validIP6)
	}
}

func TestValidFor_ValidMixed(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{validIP4})

	err1 := id.ValidFor(validDNS + ":" + validPort)
	require.NoError(t, err1)
	err2 := id.ValidFor(validIP4 + ":" + validPort)
	require.NoError(t, err2)
}

func TestValidFor_InvalidMixed(t *testing.T) {
	id := createMockIdentity([]string{validDNS}, []string{validIP4})

	err1 := id.ValidFor(invalidDNS + ":" + validPort)
	require.True(t, errors.Is(err1, ErrInvalidAddressForIdentity))
	var addrErr1 *AddressError
	if errors.As(err1, &addrErr1) {
		require.Equal(t, addrErr1.Host, invalidDNS)
		require.Contains(t, addrErr1.ValidFor, validDNS)
		require.Contains(t, addrErr1.ValidFor, validIP4)
	}

	err2 := id.ValidFor(invalidIP4 + ":" + validPort)
	require.True(t, errors.Is(err2, ErrInvalidAddressForIdentity))
	var addrErr2 *AddressError
	if errors.As(err2, &addrErr2) {
		require.Equal(t, addrErr2.Host, invalidIP4)
		require.Contains(t, addrErr2.ValidFor, validDNS)
		require.Contains(t, addrErr2.ValidFor, validIP4)
	}
}

func TestValidFor_NoCerts(t *testing.T) {
	id := createMockIdentity([]string{}, []string{})

	err := id.ValidFor(validDNS + ":" + validPort)
	require.True(t, errors.Is(err, ErrInvalidAddressForIdentity))
	var addrErr *AddressError
	if errors.As(err, &addrErr) {
		require.Equal(t, addrErr.Host, validDNS)
		require.Empty(t, addrErr.ValidFor)
	}
}

func TestValidFor_ExpandedIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{expandedIPv6})

	err := id.ValidFor("[" + expandedIPv6 + "]:" + validPort)
	require.NoError(t, err)
}

func TestValidFor_CompressedIPv6(t *testing.T) {
	id := createMockIdentity([]string{}, []string{compressedIPv6})

	err := id.ValidFor("[" + compressedIPv6 + "]:" + validPort)
	require.NoError(t, err)
}

func TestValidFor_ExpandedIPv6_MatchesCompressed(t *testing.T) {
	id := createMockIdentity([]string{}, []string{expandedIPv6})

	err := id.ValidFor("[" + compressedIPv6 + "]:" + validPort)
	require.NoError(t, err)
}

func TestValidFor_CompressedIPv6_MatchesExpanded(t *testing.T) {
	id := createMockIdentity([]string{}, []string{compressedIPv6})

	err := id.ValidFor("[" + expandedIPv6 + "]:" + validPort)
	require.NoError(t, err)
}

func TestValidFor_InvalidAddress(t *testing.T) {
	id := createMockIdentity([]string{""}, []string{})

	err := id.ValidFor("tls:" + validPort)
	require.ErrorIs(t, err, ErrInvalidAddress)
}
