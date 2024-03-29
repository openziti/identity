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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"math/big"
	"os"
	"testing"
)

func mkCert(cn string, dns []string) (crypto.Signer, *x509.Certificate) {
	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: big.NewInt(169),

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},

		DNSNames: dns,
	}
	return key, cert
}

func TestLoadIdentityWithPEM(t *testing.T) {
	// setup
	key, cert := mkCert("Test Name", []string{"test.netfoundry.io"})

	keyDer, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	keyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
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
	assert.Equal(t, key.Public(), id.Cert().Leaf.PublicKey)

}

func TestLoadIdentityWithPEMChain(t *testing.T) {
	// setup
	parentKey, parentCert := mkCert("Parent", []string{})
	parentDer, _ := x509.CreateCertificate(rand.Reader, parentCert, parentCert, parentKey.Public(), parentKey)

	key, cert := mkCert("Test Child", []string{"client.netfoundry.io"})
	certDer, _ := x509.CreateCertificate(rand.Reader, cert, parentCert, key.Public(), parentKey)

	keyDer, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	keyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	parentPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: parentDer,
	}

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	cfg := Config{
		Key:  "pem:" + string(pem.EncodeToMemory(keyPem)),
		Cert: "pem:" + string(pem.EncodeToMemory(certPem)) + string(pem.EncodeToMemory(parentPem)),
	}

	id, err := LoadIdentity(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, id.Cert())
	assert.Equal(t, 2, len(id.Cert().Certificate))
	assert.NotNil(t, id.Cert().Leaf)
	assert.Equal(t, id.Cert().Leaf.Subject.CommonName, "Test Child")
	assert.Equal(t, key.Public(), id.Cert().Leaf.PublicKey)

}

func TestLoadIdentityWithAltServerCerts(t *testing.T) {
	// setup
	parentKey, parentCert := mkCert("Parent", []string{})
	parentDer, _ := x509.CreateCertificate(rand.Reader, parentCert, parentCert, parentKey.Public(), parentKey)

	childKey1, childCert1 := mkCert("Test Child 1", []string{"client1.netfoundry.io"})
	childCert1Der, _ := x509.CreateCertificate(rand.Reader, childCert1, parentCert, childKey1.Public(), parentKey)

	childKey2, childCert2 := mkCert("Test Child 2", []string{"client2.netfoundry.io"})
	childCert2Der, _ := x509.CreateCertificate(rand.Reader, childCert2, parentCert, childKey2.Public(), parentKey)

	childKey3, childCert3 := mkCert("Test Child 3", []string{"client3.netfoundry.io"})
	childCert3Der, _ := x509.CreateCertificate(rand.Reader, childCert3, parentCert, childKey3.Public(), parentKey)

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
		assert.Equal(t, "Test Child 1", id.Cert().Leaf.Subject.CommonName)
		assert.Equal(t, childKey1.Public(), id.Cert().Leaf.PublicKey)
	})

	t.Run("has the correct server certificates", func(t *testing.T) {
		serverTlsCerts := id.ServerCert()

		certsToKeys := map[any]*ecdsa.PrivateKey{
			childCert2.Subject.String(): childKey2.(*ecdsa.PrivateKey),
			childCert3.Subject.String(): childKey3.(*ecdsa.PrivateKey),
		}

		foundServerCerts := map[string]bool{
			childCert2.Subject.String(): false,
			childCert3.Subject.String(): false,
		}

		for _, cert := range serverTlsCerts {
			if certsToKeys[cert.Leaf.Subject.String()].Equal(cert.PrivateKey) {
				foundServerCerts[cert.Leaf.Subject.String()] = true
			}
		}

		for subject, found := range foundServerCerts {
			assert.True(t, found, "certificate %s was not found in the TLS config", subject)
		}
	})

}

func TestLoadIdentityWithFile(t *testing.T) {
	// setup
	key, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)

	keyDer, _ := x509.MarshalECPrivateKey(key)
	keyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	keyFile, _ := os.CreateTemp(os.TempDir(), "test-key")

	defer os.Remove(keyFile.Name())

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Name",
		},
		SerialNumber: big.NewInt(169),

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},

		DNSNames: []string{
			"test.netfoundry.io",
		},
	}

	certDer, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	assert.NoError(t, err)

	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	certFile, _ := os.CreateTemp(os.TempDir(), "test-cert")
	defer os.Remove(certFile.Name())

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
	assert.Equal(t, key, id.Cert().PrivateKey)

}
