/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/openziti/identity/certtools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func Test_LoadIdentityWithPEM(t *testing.T) {
	// setup
	key, certTemplate := mkServerAndClientCert("Identity With PEM", []string{"test.netfoundry.io"})

	keyDer, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	keyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDer)
	assert.NoError(t, err)

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	cfg := Config{
		Key:  "pem:" + string(pem.EncodeToMemory(keyPem)),
		Cert: "pem:" + string(pem.EncodeToMemory(certPem)),
	}

	id, err := LoadIdentity(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, id.Cert())
	assert.NotNil(t, id.Cert().Leaf)
	assert.True(t, cert.Equal(id.Cert().Leaf))

}

func Test_LoadIdentityWithPEMChain(t *testing.T) {
	// setup
	caKey, caCertTemplate := mkCaCert("Parent CA 1")
	caDer, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	assert.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDer)
	assert.NoError(t, err)

	key, certTemplate := mkServerAndClientCert("Test Child", []string{"client.netfoundry.io"})
	certDer, err := x509.CreateCertificate(rand.Reader, certTemplate, caCertTemplate, key.Public(), caKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDer)
	assert.NoError(t, err)

	keyDer, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	keyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	caPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDer,
	}

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	cfg := Config{
		Key:  "pem:" + string(pem.EncodeToMemory(keyPem)),
		Cert: "pem:" + string(pem.EncodeToMemory(certPem)) + string(pem.EncodeToMemory(caPem)),
	}

	id, err := LoadIdentity(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, id.Cert())
	assert.Equal(t, 2, len(id.Cert().Certificate))
	assert.NotNil(t, id.Cert().Leaf)
	assert.True(t, id.Cert().Leaf.Equal(cert))

	// verify CA cert is after leaf
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(caCert.Raw, id.Cert().Certificate[1]))

}

func Test_CheckServerCertSansForConflicts(t *testing.T) {

	t.Run("no conflicts found", func(t *testing.T) {
		caKey, caCertTemplate := mkCaCert("Parent CA")
		parentDer, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
		assert.NoError(t, err)

		childKey1, childCert1 := mkClientCert("Test Child 1")
		childCert1Der, err := x509.CreateCertificate(rand.Reader, childCert1, caCertTemplate, childKey1.Public(), caKey)
		assert.NoError(t, err)

		childKey2, childCert2 := mkServerCert("Test Child 2", []string{"client2.netfoundry.io"}, []net.IP{net.ParseIP("127.0.0.1")})
		childCert2Der, err := x509.CreateCertificate(rand.Reader, childCert2, caCertTemplate, childKey2.Public(), caKey)
		assert.NoError(t, err)

		childKey3, childCert3 := mkServerCert("Test Child 3", []string{"client3.netfoundry.io"}, []net.IP{net.ParseIP("10.8.0.1")})
		childCert3Der, err := x509.CreateCertificate(rand.Reader, childCert3, caCertTemplate, childKey3.Public(), caKey)
		assert.NoError(t, err)

		childKey4, childCert4 := mkServerCert("Test Child 4", []string{"client4.netfoundry.io"}, []net.IP{net.ParseIP("192.168.0.1")})
		childCert4Der, err := x509.CreateCertificate(rand.Reader, childCert4, caCertTemplate, childKey4.Public(), caKey)
		assert.NoError(t, err)

		childKey1Der, _ := x509.MarshalECPrivateKey(childKey1.(*ecdsa.PrivateKey))
		childKey1Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey1Der,
		}

		childKey2Der, _ := x509.MarshalECPrivateKey(childKey2.(*ecdsa.PrivateKey))
		childKey2Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey2Der,
		}

		childKey3Der, _ := x509.MarshalECPrivateKey(childKey3.(*ecdsa.PrivateKey))
		childKey3Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey3Der,
		}

		childKey4Der, _ := x509.MarshalECPrivateKey(childKey4.(*ecdsa.PrivateKey))
		childKey4Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey4Der,
		}

		parentPem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: parentDer,
		}

		childCert1Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert1Der,
		}

		childCert2Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert2Der,
		}

		childCert3Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert3Der,
		}

		childCert4Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert4Der,
		}

		cfg := Config{
			Key:        "pem:" + string(pem.EncodeToMemory(childKey1Pem)),
			Cert:       "pem:" + string(pem.EncodeToMemory(childCert1Pem)) + string(pem.EncodeToMemory(parentPem)),
			ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey2Pem)),
			ServerCert: "pem:" + string(pem.EncodeToMemory(childCert2Pem)) + string(pem.EncodeToMemory(parentPem)),
			AltServerCerts: []ServerPair{
				{
					ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey3Pem)),
					ServerCert: "pem:" + string(pem.EncodeToMemory(childCert3Pem)) + string(pem.EncodeToMemory(parentPem)),
				},
				{
					ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey4Pem)),
					ServerCert: "pem:" + string(pem.EncodeToMemory(childCert4Pem)) + string(pem.EncodeToMemory(parentPem)),
				},
			},
		}

		id, err := LoadIdentity(cfg)

		t.Run("loads without error", func(t *testing.T) {
			assert.NoError(t, err)
		})

		t.Run("check for sans conflicts returns no conflict", func(t *testing.T) {
			req := require.New(t)
			conflicts := id.CheckServerCertSansForConflicts()
			req.Empty(conflicts)
		})
	})

	t.Run("conflicts found", func(t *testing.T) {
		caKey, caCertTemplate := mkCaCert("Parent CA")
		parentDer, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
		assert.NoError(t, err)

		childKey1, childCert1 := mkClientCert("Test Child 1")
		childCert1Der, err := x509.CreateCertificate(rand.Reader, childCert1, caCertTemplate, childKey1.Public(), caKey)
		assert.NoError(t, err)

		childKey2, childCert2 := mkServerCert("Test Child 2", []string{"client2.netfoundry.io"}, []net.IP{net.ParseIP("127.0.0.1")})
		childCert2Der, err := x509.CreateCertificate(rand.Reader, childCert2, caCertTemplate, childKey2.Public(), caKey)
		assert.NoError(t, err)

		//dupes ip from childCert2
		childKey3, childCert3 := mkServerCert("Test Child 3", []string{"client3.netfoundry.io"}, []net.IP{net.ParseIP("127.0.0.1")})
		childCert3Der, err := x509.CreateCertificate(rand.Reader, childCert3, caCertTemplate, childKey3.Public(), caKey)
		assert.NoError(t, err)

		//dupes dns from childCert3
		childKey4, childCert4 := mkServerCert("Test Child 4", []string{"client3.netfoundry.io"}, []net.IP{net.ParseIP("192.168.0.1")})
		childCert4Der, err := x509.CreateCertificate(rand.Reader, childCert4, caCertTemplate, childKey4.Public(), caKey)
		assert.NoError(t, err)

		childKey1Der, _ := x509.MarshalECPrivateKey(childKey1.(*ecdsa.PrivateKey))
		childKey1Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey1Der,
		}

		childKey2Der, _ := x509.MarshalECPrivateKey(childKey2.(*ecdsa.PrivateKey))
		childKey2Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey2Der,
		}

		childKey3Der, _ := x509.MarshalECPrivateKey(childKey3.(*ecdsa.PrivateKey))
		childKey3Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey3Der,
		}

		childKey4Der, _ := x509.MarshalECPrivateKey(childKey4.(*ecdsa.PrivateKey))
		childKey4Pem := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: childKey4Der,
		}

		parentPem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: parentDer,
		}

		childCert1Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert1Der,
		}

		childCert2Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert2Der,
		}

		childCert3Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert3Der,
		}

		childCert4Pem := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: childCert4Der,
		}

		cfg := Config{
			Key:        "pem:" + string(pem.EncodeToMemory(childKey1Pem)),
			Cert:       "pem:" + string(pem.EncodeToMemory(childCert1Pem)) + string(pem.EncodeToMemory(parentPem)),
			ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey2Pem)),
			ServerCert: "pem:" + string(pem.EncodeToMemory(childCert2Pem)) + string(pem.EncodeToMemory(parentPem)),
			AltServerCerts: []ServerPair{
				{
					ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey3Pem)),
					ServerCert: "pem:" + string(pem.EncodeToMemory(childCert3Pem)) + string(pem.EncodeToMemory(parentPem)),
				},
				{
					ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey4Pem)),
					ServerCert: "pem:" + string(pem.EncodeToMemory(childCert4Pem)) + string(pem.EncodeToMemory(parentPem)),
				},
			},
		}

		id, err := LoadIdentity(cfg)

		t.Run("loads without error", func(t *testing.T) {
			assert.NoError(t, err)
		})

		t.Run("check for sans conflicts returns no conflict", func(t *testing.T) {
			req := require.New(t)
			conflicts := id.CheckServerCertSansForConflicts()
			req.Len(conflicts, 2)

			req.Equal("127.0.0.1", conflicts[0].HostOrIp)
			req.Equal(conflicts[0].Certificates[0].SerialNumber, childCert2.SerialNumber)
			req.Equal(conflicts[0].Certificates[1].SerialNumber, childCert3.SerialNumber)

			req.Equal("client3.netfoundry.io", conflicts[1].HostOrIp)
			req.Equal(conflicts[1].Certificates[0].SerialNumber, childCert3.SerialNumber)
			req.Equal(conflicts[1].Certificates[1].SerialNumber, childCert4.SerialNumber)
		})
	})
}

func Test_LoadIdentityWithAltServerCerts(t *testing.T) {
	// setup
	caKey, caCertTemplate := mkCaCert("Parent CA")
	parentDer, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	assert.NoError(t, err)

	childKey1, childCert1 := mkClientCert("Test Child 1")
	childCert1Der, err := x509.CreateCertificate(rand.Reader, childCert1, caCertTemplate, childKey1.Public(), caKey)
	assert.NoError(t, err)

	childKey2, childCert2 := mkServerCert("Test Child 2", []string{"client2.netfoundry.io"}, []net.IP{net.ParseIP("127.0.0.1")})
	childCert2Der, err := x509.CreateCertificate(rand.Reader, childCert2, caCertTemplate, childKey2.Public(), caKey)
	assert.NoError(t, err)

	childKey3, childCert3 := mkServerCert("Test Child 3", []string{"client3.netfoundry.io"}, []net.IP{net.ParseIP("10.8.0.1")})
	childCert3Der, err := x509.CreateCertificate(rand.Reader, childCert3, caCertTemplate, childKey3.Public(), caKey)
	assert.NoError(t, err)

	childKey4, childCert4 := mkServerCert("Test Child 4", []string{"client4.netfoundry.io"}, []net.IP{net.ParseIP("192.168.0.1")})
	childCert4Der, err := x509.CreateCertificate(rand.Reader, childCert4, caCertTemplate, childKey4.Public(), caKey)
	assert.NoError(t, err)

	childKey1Der, _ := x509.MarshalECPrivateKey(childKey1.(*ecdsa.PrivateKey))
	childKey1Pem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: childKey1Der,
	}

	childKey2Der, _ := x509.MarshalECPrivateKey(childKey2.(*ecdsa.PrivateKey))
	childKey2Pem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: childKey2Der,
	}

	childKey3Der, _ := x509.MarshalECPrivateKey(childKey3.(*ecdsa.PrivateKey))
	childKey3Pem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: childKey3Der,
	}

	childKey4Der, _ := x509.MarshalECPrivateKey(childKey4.(*ecdsa.PrivateKey))
	childKey4Pem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: childKey4Der,
	}

	parentPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: parentDer,
	}

	childCert1Pem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: childCert1Der,
	}

	childCert2Pem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: childCert2Der,
	}

	childCert3Pem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: childCert3Der,
	}

	childCert4Pem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: childCert4Der,
	}

	cfg := Config{
		Key:        "pem:" + string(pem.EncodeToMemory(childKey1Pem)),
		Cert:       "pem:" + string(pem.EncodeToMemory(childCert1Pem)) + string(pem.EncodeToMemory(parentPem)),
		ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey2Pem)),
		ServerCert: "pem:" + string(pem.EncodeToMemory(childCert2Pem)) + string(pem.EncodeToMemory(parentPem)),
		AltServerCerts: []ServerPair{
			{
				ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey3Pem)),
				ServerCert: "pem:" + string(pem.EncodeToMemory(childCert3Pem)) + string(pem.EncodeToMemory(parentPem)),
			},
			{
				ServerKey:  "pem:" + string(pem.EncodeToMemory(childKey4Pem)),
				ServerCert: "pem:" + string(pem.EncodeToMemory(childCert4Pem)) + string(pem.EncodeToMemory(parentPem)),
			},
		},
	}

	id, err := LoadIdentity(cfg)

	t.Run("loads without error", func(t *testing.T) {
		assert.NoError(t, err)
	})

	t.Run("has the correct client certificate", func(t *testing.T) {
		assert.NotNil(t, id.Cert())
		assert.Equal(t, 2, len(id.Cert().Certificate))
		assert.NotNil(t, id.Cert().Leaf)
		assert.Equal(t, childCert1Der, id.Cert().Leaf.Raw)
	})

	t.Run("has the correct server certificates", func(t *testing.T) {
		serverTlsCerts := id.ServerCert()

		childCert2Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert2Der, 20))
		childCert3Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert3Der, 20))
		childCert4Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert4Der, 20))

		certsToKeys := map[string]*ecdsa.PrivateKey{
			childCert2Print: childKey2.(*ecdsa.PrivateKey),
			childCert3Print: childKey3.(*ecdsa.PrivateKey),
			childCert4Print: childKey4.(*ecdsa.PrivateKey),
		}

		foundServerCerts := map[string]bool{
			childCert2Print: false,
			childCert3Print: false,
			childCert4Print: false,
		}

		for _, cert := range serverTlsCerts {
			curPrint := fmt.Sprintf("%x", certtools.Shake256HexN(cert.Leaf.Raw, 20))
			if certsToKeys[curPrint].Equal(cert.PrivateKey) {
				foundServerCerts[curPrint] = true
			}
		}

		assert.True(t, foundServerCerts[childCert2Print], "child cert 2 was not found")
		assert.True(t, foundServerCerts[childCert3Print], "child cert 3 was not found")
	})

	t.Run("returns the correct x509 certificates", func(t *testing.T) {
		t.Run("the correct active server chains", func(t *testing.T) {
			req := require.New(t)
			chains := id.GetX509ActiveServerCertChains()

			chainMap := map[string][]string{}

			for _, chain := range chains {
				leafPrint := fmt.Sprintf("%x", certtools.Shake256HexN(chain[0].Raw, 20))
				for i, cert := range chain {
					if i == 0 {
						continue
					}
					chainMap[leafPrint] = append(chainMap[leafPrint], fmt.Sprintf("%x", certtools.Shake256HexN(cert.Raw, 20)))
				}
			}
			cert2Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert2Der, 20))
			cert3Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert3Der, 20))
			cert4Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert4Der, 20))
			parentPrint := fmt.Sprintf("%x", certtools.Shake256HexN(parentDer, 20))

			expectedMap := map[string][]string{
				cert2Print: {parentPrint},
				cert3Print: {parentPrint},
				cert4Print: {parentPrint},
			}

			req.Len(chainMap, 3)
			req.ElementsMatch(mapKeys(chainMap), mapKeys(expectedMap))

			for k, v := range expectedMap {
				req.ElementsMatch(v, chainMap[k])
			}
		})

		t.Run("the correct active client chain", func(t *testing.T) {
			req := require.New(t)
			clientChain := id.GetX509ActiveClientCertChain()

			var actualCerts []string

			for _, cert := range clientChain {
				actualCerts = append(actualCerts, fmt.Sprintf("%x", certtools.Shake256HexN(cert.Raw, 20)))
			}

			var expectedCerts []string

			for _, tlsCert := range id.Cert().Certificate {
				expectedCerts = append(expectedCerts, fmt.Sprintf("%x", certtools.Shake256HexN(tlsCert, 20)))
			}

			req.Len(actualCerts, 2)
			req.Len(expectedCerts, 2)

			req.Equal(expectedCerts[0], actualCerts[0])
			req.Equal(expectedCerts[1], actualCerts[1])
		})

		t.Run("the correct identity server cert chain", func(t *testing.T) {

			req := require.New(t)
			serverChain := id.GetX509IdentityServerCertChain()

			var actualCerts []string

			for _, cert := range serverChain {
				actualCerts = append(actualCerts, fmt.Sprintf("%x", certtools.Shake256HexN(cert.Raw, 20)))
			}

			var expectedCerts []string
			parsedCerts, err := LoadCert(id.GetConfig().ServerCert)
			req.NoError(err)

			for _, cert := range parsedCerts {
				expectedCerts = append(expectedCerts, fmt.Sprintf("%x", certtools.Shake256HexN(cert.Raw, 20)))
			}

			req.Len(actualCerts, 2)
			req.Len(expectedCerts, 2)

			req.Equal(expectedCerts[0], actualCerts[0])
			req.Equal(expectedCerts[1], actualCerts[1])

		})
		t.Run("the correct alt server cert chains", func(t *testing.T) {

			req := require.New(t)
			chains := id.GetX509IdentityAltCertCertChains()

			chainMap := map[string][]string{}

			for _, chain := range chains {
				leafPrint := fmt.Sprintf("%x", certtools.Shake256HexN(chain[0].Raw, 20))
				for i, cert := range chain {
					if i == 0 {
						continue
					}
					chainMap[leafPrint] = append(chainMap[leafPrint], fmt.Sprintf("%x", certtools.Shake256HexN(cert.Raw, 20)))
				}
			}

			cert3Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert3Der, 20))
			cert4Print := fmt.Sprintf("%x", certtools.Shake256HexN(childCert4Der, 20))
			parentPrint := fmt.Sprintf("%x", certtools.Shake256HexN(parentDer, 20))

			expectedMap := map[string][]string{
				cert3Print: {parentPrint},
				cert4Print: {parentPrint},
			}

			req.Len(chainMap, 2)
			req.ElementsMatch(mapKeys(chainMap), mapKeys(expectedMap))

			for k, v := range expectedMap {
				req.ElementsMatch(v, chainMap[k])
			}
		})
	})

}

func Test_LoadIdentityWithFile(t *testing.T) {
	// setup
	key, cert := mkServerAndClientCert("File Test Cert", []string{"file.test.netfoundry.io"})

	keyDer, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	keyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	keyFile, _ := os.CreateTemp(os.TempDir(), "test-key")

	defer func() { _ = os.Remove(keyFile.Name()) }()

	certDer, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	assert.NoError(t, err)

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	certFile, _ := os.CreateTemp(os.TempDir(), "test-cert")
	defer func() { _ = os.Remove(certFile.Name()) }()

	err = pem.Encode(keyFile, keyPem)
	assert.NoError(t, err)

	err = pem.Encode(certFile, certPem)
	assert.NoError(t, err)

	cfg := Config{
		Key:  "file://" + keyFile.Name(),
		Cert: "file://" + certFile.Name(),
	}

	id, err := LoadIdentity(cfg)
	assert.NoError(t, err)
	assert.Equal(t, certDer, id.Cert().Leaf.Raw)

}

// helpers

var testSerial = int64(0)

func mkCaCert(cn string) (crypto.Signer, *x509.Certificate) {
	testSerial++

	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject: pkix.Name{
			Organization:       []string{"OpenZiti Identity Tests"},
			OrganizationalUnit: []string{"CA Certs"},
			CommonName:         cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{}, // CAs typically don’t need ExtKeyUsage
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	return key, cert
}

func mkServerAndClientCert(cn string, dns []string) (crypto.Signer, *x509.Certificate) {
	testSerial++

	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject: pkix.Name{
			Organization:       []string{"OpenZiti Identity Tests"},
			OrganizationalUnit: []string{"Server And Client Certs"},
			CommonName:         cn,
		},
		DNSNames:              dns,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	return key, cert
}

func mkServerCert(cn string, dns []string, ips []net.IP) (crypto.Signer, *x509.Certificate) {
	testSerial++

	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject: pkix.Name{
			Organization:       []string{"OpenZiti Identity Tests"},
			OrganizationalUnit: []string{"Server Certs"},
			CommonName:         cn,
		},
		DNSNames:              dns,
		IPAddresses:           ips,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return key, cert
}

func mkClientCert(cn string) (crypto.Signer, *x509.Certificate) {
	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject: pkix.Name{
			Organization:       []string{"OpenZiti Identity Tests"},
			OrganizationalUnit: []string{"Client Certs"},
			CommonName:         cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	return key, cert
}

func mapKeys[T comparable, K any](m map[T]K) []T {
	result := make([]T, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
