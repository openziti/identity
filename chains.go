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
	"crypto/tls"
	"crypto/x509"
)

// AssembleServerChains takes in an array of certificates, finds all certificates with
// x509.ExtKeyUsageAny or x509.ExtKeyUsageServerAuth and builds an array of leaf-first
// chains.
func AssembleServerChains(certs []*x509.Certificate) ([][]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, nil
	}

	var chains [][]*x509.Certificate

	skidToCert := map[string]*x509.Certificate{}

	var serverCerts []*x509.Certificate

	for _, cert := range certs {
		if !cert.IsCA && (len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0) {
			serverCerts = append(serverCerts, cert)
		}

		if len(cert.SubjectKeyId) != 0 {
			skidToCert[string(cert.SubjectKeyId)] = cert
		}
	}

	for _, serverCert := range serverCerts {
		chain := buildChain(serverCert, skidToCert, certs)
		chains = append(chains, chain)
	}

	return chains, nil
}

// buildChain will build as much of a chain as possible from startingLeaf up. It will attempt to use Authority and
// Subject Key Ids if possible. If not it will use subject string and signature checking.
func buildChain(startingLeaf *x509.Certificate, skidToCert map[string]*x509.Certificate, certs []*x509.Certificate) []*x509.Certificate {

	var chain []*x509.Certificate

	current := startingLeaf

	for current != nil {
		chain = append(chain, current)

		//check to see if we are the root
		if current.IsCA {
			if err := current.CheckSignatureFrom(current); err == nil {
				break
			}
		}

		//search by akid
		if len(current.AuthorityKeyId) != 0 && string(current.AuthorityKeyId) != string(current.SubjectKeyId) {
			if next, ok := skidToCert[string(current.AuthorityKeyId)]; ok {
				current = next
				continue
			}
		}

		//search by subject info and signing
		for _, next := range certs {
			if next.IsCA && next.Subject.String() == current.Issuer.String() {
				if err := current.CheckSignatureFrom(next); err == nil {
					current = next
					continue
				}
			}
		}

		//no parent found
		current = nil
	}

	return chain
}

// ChainsToTlsCerts converts and array of x509 certificate chains to an array of tls.Certificates (which
// have their own internal arrays of raw certificates). It is assumed the same private key is used for
// all chains.
func ChainsToTlsCerts(chains [][]*x509.Certificate, key crypto.PrivateKey) []*tls.Certificate {
	tlsCerts := make([]*tls.Certificate, len(chains))

	for chainIdx, chain := range chains {
		tlsCerts[chainIdx] = &tls.Certificate{
			Certificate: make([][]byte, len(chain)),
			Leaf:        chain[0],
			PrivateKey:  key,
		}

		for certIdx, cert := range chain {
			tlsCerts[chainIdx].Certificate[certIdx] = cert.Raw
		}
	}

	return tlsCerts
}
