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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func Test_Assemble(t *testing.T) {
	t.Run("returns nil and no error on nil certs", func(t *testing.T) {
		req := require.New(t)

		ret, err := AssembleServerChains(nil)

		req.Nil(ret)
		req.NoError(err)
	})

	t.Run("returns nil and no error on 0 certs", func(t *testing.T) {
		req := require.New(t)

		ret, err := AssembleServerChains([]*x509.Certificate{})

		req.Nil(ret)
		req.NoError(err)
	})

	t.Run("returns 1 chain of 1 cert with 1 root given only 1 leaf all with AKIDs", func(t *testing.T) {
		req := require.New(t)
		root := newRootCa()
		leaf := root.NewLeafWithAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{leaf.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 1)
		req.Len(ret[0], 1)
		req.Equal(ret[0][0], leaf.cert)
	})

	t.Run("returns 1 chain of 1 cert with 2 root given only 1 leaf with and without AKIDs", func(t *testing.T) {
		req := require.New(t)
		root := newRootCa()
		leaf := root.NewLeafWithAKID()

		root2 := newRootCa()
		intermediate2 := root2.NewIntermediateWithoutAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{leaf.cert, root2.cert, intermediate2.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 1)
		req.Len(ret[0], 1)
		req.Equal(ret[0][0], leaf.cert)
	})

	t.Run("returns 1 chain of 1 cert with 1 root given only 1 leaf all without AKIDs", func(t *testing.T) {
		req := require.New(t)
		root := newRootCa()
		leaf := root.NewLeafWithoutAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{leaf.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 1)
		req.Len(ret[0], 1)
		req.Equal(ret[0][0], leaf.cert)
	})

	t.Run("returns 2 chains for two different CAs all with AKIDs", func(t *testing.T) {
		req := require.New(t)

		root1 := newRootCa()
		leaf1 := root1.NewLeafWithAKID()

		root2 := newRootCa()
		intermediate2 := root2.NewIntermediateWithAKID()
		leaf2 := intermediate2.NewLeafWithAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{root1.cert, leaf1.cert, root2.cert, intermediate2.cert, leaf2.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 2)

		// root1 -> leaf2
		req.Len(ret[0], 2)
		req.Equal(ret[0][0], leaf1.cert)
		req.Equal(ret[0][1], root1.cert)

		// root2 -> intermediate2 -> leaf 2

		req.Len(ret[1], 3)
		req.Equal(ret[1][0], leaf2.cert)
		req.Equal(ret[1][1], intermediate2.cert)
		req.Equal(ret[1][2], root2.cert)
	})

	t.Run("returns 2 chains for two different CAs all without AKIDs", func(t *testing.T) {
		req := require.New(t)

		root1 := newRootCa()
		leaf1 := root1.NewLeafWithoutAKID()

		root2 := newRootCa()
		intermediate2 := root2.NewIntermediateWithoutAKID()
		leaf2 := intermediate2.NewLeafWithoutAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{root1.cert, leaf1.cert, root2.cert, intermediate2.cert, leaf2.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 2)

		// root1 -> leaf2
		req.Len(ret[0], 2)
		req.Equal(ret[0][0], leaf1.cert)
		req.Equal(ret[0][1], root1.cert)

		// root2 -> intermediate2 -> leaf 2

		req.Len(ret[1], 3)
		req.Equal(ret[1][0], leaf2.cert)
		req.Equal(ret[1][1], intermediate2.cert)
		req.Equal(ret[1][2], root2.cert)
	})

	t.Run("returns 1 chain for ca>intermediate>leaf + random intermediates and CAs with AKIDs", func(t *testing.T) {
		req := require.New(t)

		root1 := newRootCa()
		intermediate1 := root1.NewIntermediateWithAKID()

		root2 := newRootCa()
		intermediate2 := root2.NewIntermediateWithAKID()
		leaf2 := intermediate2.NewLeafWithAKID()

		root3 := newRootCa()
		intermediate3 := root3.NewIntermediateWithAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{root1.cert, intermediate1.cert, root2.cert, intermediate2.cert, leaf2.cert, intermediate3.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 1)

		// root1 -> leaf2
		req.Len(ret[0], 3)
		req.Equal(ret[0][0], leaf2.cert)
		req.Equal(ret[0][1], intermediate2.cert)
		req.Equal(ret[0][2], root2.cert)
	})

	t.Run("returns 1 chain ca>intermediate>leaf with mixed AKID/no AKID", func(t *testing.T) {
		req := require.New(t)

		root1 := newRootCa()
		intermediate1 := root1.NewIntermediateWithoutAKID()
		leaf1 := intermediate1.NewLeafWithAKID()

		ret, err := AssembleServerChains([]*x509.Certificate{root1.cert, intermediate1.cert, leaf1.cert})

		req.NoError(err)
		req.NotNil(ret)
		req.Len(ret, 1)

		// root1 -> intermediate1 -> leaf 2

		req.Len(ret[0], 3)
		req.Equal(ret[0][0], leaf1.cert)
		req.Equal(ret[0][1], intermediate1.cert)
		req.Equal(ret[0][2], root1.cert)
	})

	t.Run("can host a http server for 127.0.0.1 and localhost from two different certificates", func(t *testing.T) {
		req := require.New(t)
		root := newRootCa()

		leafKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(err)
		}

		ipLeaf := root.NewLeaf(leafKey, func(certificate *x509.Certificate) {
			certificate.IPAddresses = append(certificate.IPAddresses, net.ParseIP("127.0.0.1"))
		})

		dnsLeaf := root.NewLeaf(leafKey, func(certificate *x509.Certificate) {
			certificate.DNSNames = append(certificate.DNSNames, "localhost")
		})

		keyPem := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(leafKey),
		}))

		serverPem := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ipLeaf.cert.Raw,
		}))

		serverPem = serverPem + "\n" + string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: dnsLeaf.cert.Raw,
		}))

		caPem := string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: root.cert.Raw,
		}))

		identityCfg := Config{
			Key:        "pem:" + keyPem,
			Cert:       "pem:" + serverPem,
			ServerCert: "pem:" + serverPem,
			ServerKey:  "pem:" + keyPem,
			CA:         "pem:" + caPem,
		}

		id, err := LoadIdentity(identityCfg)

		req.NoError(err)

		tlsConfig := id.ServerTLSConfig()

		tlsConfig.ClientAuth = tls.NoClientCert

		server := http.Server{
			Addr: "0.0.0.0:8429",
			Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = writer.Write([]byte("hi"))
			}),
			TLSConfig:         tlsConfig,
			ReadTimeout:       0,
			ReadHeaderTimeout: 0,
			WriteTimeout:      0,
			IdleTimeout:       0,
			MaxHeaderBytes:    0,
			TLSNextProto:      nil,
			ConnState:         nil,
			ErrorLog:          nil,
			BaseContext:       nil,
			ConnContext:       nil,
		}

		go func() {
			_ = server.ListenAndServeTLS("", "")
		}()

		defer func() {
			_ = server.Shutdown(context.Background())
		}()

		certPool := x509.NewCertPool()

		certPool.AddCert(root.cert)

		dialer := net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 15 * time.Second,
		}

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},

			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       15 * time.Second,
		}

		t.Run("can perform a get via localhost", func(t *testing.T) {
			req := require.New(t)

			resp, err := httpClient.Get("https://localhost:8429")

			req.NoError(err)
			req.Equal(http.StatusOK, resp.StatusCode)

			body, err := ioutil.ReadAll(resp.Body)
			req.NoError(err)
			req.Equal([]byte("hi"), body)
		})

		t.Run("can perform a get via 127.0.0.1", func(t *testing.T) {
			req := require.New(t)

			resp, err := httpClient.Get("https://127.0.0.1:8429")

			req.NoError(err)
			req.Equal(http.StatusOK, resp.StatusCode)

			body, err := ioutil.ReadAll(resp.Body)
			req.NoError(err)
			req.Equal([]byte("hi"), body)
		})

	})

}

var currentSerial int64 = 1

type certPair struct {
	cert *x509.Certificate
	key  any
}

type testCa struct {
	certPair
}

func newRootCa() *testCa {
	currentSerial++

	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	root := &x509.Certificate{
		SerialNumber: big.NewInt(currentSerial),
		Subject: pkix.Name{
			CommonName:    "root-" + strconv.FormatInt(currentSerial, 10),
			Organization:  []string{"FAKE, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Nowhere"},
			StreetAddress: []string{"Nowhere Road"},
			PostalCode:    []string{"55555"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootBytes, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)

	if err != nil {
		panic(err)
	}

	root, err = x509.ParseCertificate(rootBytes)

	if err != nil {
		panic(err)
	}

	return &testCa{
		certPair{
			cert: root,
			key:  rootKey,
		},
	}
}

func (ca *testCa) NewIntermediateWithAKID() *testCa {
	currentSerial++

	intermediate := &x509.Certificate{
		SerialNumber: big.NewInt(currentSerial),
		Subject: pkix.Name{
			CommonName:    "intermediate-" + strconv.FormatInt(currentSerial, 10),
			Organization:  []string{"FAKE, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Nowhere"},
			StreetAddress: []string{"Nowhere Road"},
			PostalCode:    []string{"55555"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		AuthorityKeyId:        ca.cert.SubjectKeyId,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	intermediateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	intermediateBytes, err := x509.CreateCertificate(rand.Reader, intermediate, ca.cert, &intermediateKey.PublicKey, ca.key)

	if err != nil {
		panic(err)
	}

	intermediate, err = x509.ParseCertificate(intermediateBytes)

	if err != nil {
		panic(err)
	}

	return &testCa{
		certPair{
			cert: intermediate,
			key:  intermediateKey,
		},
	}
}

func (ca *testCa) NewIntermediateWithoutAKID() *testCa {
	currentSerial++

	intermediate := &x509.Certificate{
		SerialNumber: big.NewInt(currentSerial),
		Subject: pkix.Name{
			CommonName:    "intermediate-" + strconv.FormatInt(currentSerial, 10),
			Organization:  []string{"FAKE, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Nowhere"},
			StreetAddress: []string{"Nowhere Road"},
			PostalCode:    []string{"55555"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	intermediateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	intermediateBytes, err := x509.CreateCertificate(rand.Reader, intermediate, ca.cert, &intermediateKey.PublicKey, ca.key)

	if err != nil {
		panic(err)
	}

	intermediate, err = x509.ParseCertificate(intermediateBytes)

	if err != nil {
		panic(err)
	}

	return &testCa{
		certPair{
			cert: intermediate,
			key:  intermediateKey,
		},
	}
}

func (ca *testCa) NewLeafWithAKID() *certPair {
	currentSerial++

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:    "leaf-" + strconv.FormatInt(currentSerial, 10),
			Organization:  []string{"FAKE, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Nowhere"},
			StreetAddress: []string{"Nowhere Road"},
			PostalCode:    []string{"55555"},
		},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		AuthorityKeyId: ca.cert.SubjectKeyId,
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	leafBytes, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, &leafKey.PublicKey, ca.key)

	if err != nil {
		panic(err)
	}

	leaf, err = x509.ParseCertificate(leafBytes)

	if err != nil {
		panic(err)
	}

	return &certPair{
		cert: leaf,
		key:  leafKey,
	}
}

func (ca *testCa) NewLeaf(leafKey *rsa.PrivateKey, alterCertFuncs ...func(certificate *x509.Certificate)) *certPair {
	currentSerial++

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:    "leaf-" + strconv.FormatInt(currentSerial, 10),
			Organization:  []string{"FAKE, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Nowhere"},
			StreetAddress: []string{"Nowhere Road"},
			PostalCode:    []string{"55555"},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	for _, f := range alterCertFuncs {
		f(leaf)
	}

	leafBytes, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, &leafKey.PublicKey, ca.key)

	if err != nil {
		panic(err)
	}

	leaf, err = x509.ParseCertificate(leafBytes)

	if err != nil {
		panic(err)
	}

	return &certPair{
		cert: leaf,
		key:  leafKey,
	}
}
func (ca *testCa) NewLeafWithoutAKID() *certPair {
	currentSerial++

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:    "leaf-" + strconv.FormatInt(currentSerial, 10),
			Organization:  []string{"FAKE, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Nowhere"},
			StreetAddress: []string{"Nowhere Road"},
			PostalCode:    []string{"55555"},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	leafBytes, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, &leafKey.PublicKey, ca.key)

	if err != nil {
		panic(err)
	}

	leaf, err = x509.ParseCertificate(leafBytes)

	if err != nil {
		panic(err)
	}

	return &certPair{
		cert: leaf,
		key:  leafKey,
	}
}
