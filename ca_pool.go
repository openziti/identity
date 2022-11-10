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
	"github.com/pkg/errors"
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

func (self *CaPool) GetChainMinusRoot(cert *x509.Certificate, extraCerts ...*x509.Certificate) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	result = append(result, cert)

	for _, extraCert := range extraCerts {
		if !extraCert.IsCA {
			return nil, errors.Errorf("found multiple leaf certs [%v and %v]", cert, extraCerts)
		}
	}

	certs := map[*x509.Certificate]struct{}{}
	self.addNonSelfSignedCasToCertsMap(certs, self.certs)
	self.addNonSelfSignedCasToCertsMap(certs, extraCerts)

	for {
		if parent := self.getParent(cert, certs); parent != nil {
			result = append(result, parent)
			cert = parent
		} else {
			return result, nil
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
