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
	"crypto/x509"
)

type CaPool struct {
	certs []*x509.Certificate
}

func NewCaPool(certs []*x509.Certificate) *CaPool {
	result := &CaPool{
		certs: certs,
	}
	return result
}

func (self *CaPool) isSelfSignedCA(cert *x509.Certificate) bool {
	return cert.IsCA && cert.CheckSignatureFrom(cert) == nil
}

// GetChainMinusRoot returns a chain from `cert` up to, but not including, the root CA if possible. If no cert is
// provided, nil is returned, if no chains is assembled the resulting chain will be the target cert only.
func (self *CaPool) GetChainMinusRoot(cert *x509.Certificate, extraCerts ...*x509.Certificate) []*x509.Certificate {
	if cert == nil {
		return nil
	}

	var result []*x509.Certificate
	result = append(result, cert)

	certs := map[*x509.Certificate]struct{}{}
	self.addNonSelfSignedCasToCertsMap(certs, self.certs)
	self.addNonSelfSignedCasToCertsMap(certs, extraCerts)

	for {
		if parent := self.getParent(cert, certs); parent != nil {
			result = append(result, parent)
			cert = parent
		} else {
			return result
		}
	}
}

// GetChain returns a chain from `cert` up and including the root CA if possible. If no cert is provided, nil is
// returned. If no chains is assembled the resulting chain will be the target cert only.
func (self *CaPool) GetChain(cert *x509.Certificate, extraCerts ...*x509.Certificate) []*x509.Certificate {
	if cert == nil {
		return nil
	}

	var result []*x509.Certificate
	result = append(result, cert)

	certs := map[*x509.Certificate]struct{}{}

	for _, curCert := range self.certs {
		certs[curCert] = struct{}{}
	}
	for _, curCert := range extraCerts {
		certs[curCert] = struct{}{}
	}

	for {
		if parent := self.getParent(cert, certs); parent != nil {
			result = append(result, parent)
			cert = parent
		} else {
			return result
		}
	}
}

func (self *CaPool) addNonSelfSignedCasToCertsMap(certMap map[*x509.Certificate]struct{}, certs []*x509.Certificate) {
	for _, cert := range certs {
		if cert.IsCA && !self.isSelfSignedCA(cert) {
			certMap[cert] = struct{}{}
		}
	}
}

func (self *CaPool) getParent(cert *x509.Certificate, certs map[*x509.Certificate]struct{}) *x509.Certificate {
	for candidate := range certs {
		if err := cert.CheckSignatureFrom(candidate); err == nil {
			delete(certs, candidate)
			return candidate
		}
	}
	return nil
}
