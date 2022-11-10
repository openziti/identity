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
	"crypto/x509"
)

type CaPool struct {
	certs   []*x509.Certificate
	parents map[*x509.Certificate]*x509.Certificate
}

func NewCaPool(certs []*x509.Certificate) *CaPool {
	result := &CaPool{
		certs:   certs,
		parents: map[*x509.Certificate]*x509.Certificate{},
	}
	result.buildParentMap()
	return result
}

func (self *CaPool) buildParentMap() {
	for _, cert := range self.certs {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			continue
		}

		for _, parent := range self.certs {
			if parent.IsCA && parent != cert && cert.Issuer.CommonName == parent.Subject.CommonName {
				if err := cert.CheckSignatureFrom(parent); err == nil {
					self.parents[cert] = parent
					break
				}
			}
		}
	}
}

func (self *CaPool) isSelfSignedCA(cert *x509.Certificate) bool {
	return cert.IsCA && cert.CheckSignatureFrom(cert) == nil
}

func (self *CaPool) GetChainMinusRoot(cert *x509.Certificate, extraCerts ...*x509.Certificate) []*x509.Certificate {
	var result []*x509.Certificate
	result = append(result, cert)

	var next *x509.Certificate
	for _, parent := range self.certs {
		if parent.IsCA && parent != cert && !self.isSelfSignedCA(parent) {
			if err := cert.CheckSignatureFrom(parent); err == nil {
				next = parent
				break
			}
		}
	}

	if next != nil {
		result = append(result, next)

		for {
			next = self.parents[next]
			if next == nil || !next.IsCA || self.isSelfSignedCA(next) {
				break
			}
			result = append(result, next)
		}
	}

	for _, extraCert := range extraCerts {
		found := false
		for _, existing := range result[1:] {
			if bytes.Equal(extraCert.Raw, existing.Raw) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, extraCert)
		}
	}

	return result
}
