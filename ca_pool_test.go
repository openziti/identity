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
	"github.com/stretchr/testify/require"
	"testing"
)

// TestCaPool directly tests the CaPool type
func TestCaPool(t *testing.T) {
	pki := newTestPki()

	t.Run("can create a new pool with 0 starting certs", func(t *testing.T) {
		req := require.New(t)
		pool := NewCaPool(nil)
		req.NotNil(pool)

		t.Run("the pool has 0 roots", func(t *testing.T) {
			req = require.New(t)
			roots := pool.Roots()
			req.Len(roots, 0)
		})

		t.Run("the pool has 0 intermediates", func(t *testing.T) {
			req = require.New(t)
			intermediates := pool.Intermediates()
			req.Len(intermediates, 0)
		})

		t.Run("building a chain results in just the leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChain(pki.LeafC.cert)

			req.Len(chain, 1)
			req.Equal(pki.LeafC.cert, chain[0])
		})

		t.Run("building a chain minus roots results in just the leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChainMinusRoot(pki.LeafC.cert)

			req.Len(chain, 1)
			req.Equal(pki.LeafC.cert, chain[0])
		})
	})

	t.Run("can create a new pool with starting certs", func(t *testing.T) {
		req := require.New(t)

		startingCerts := pki.AllCas()

		pool := NewCaPool(startingCerts)
		req.NotNil(pool)

		t.Run("the pool has 2 roots", func(t *testing.T) {
			req = require.New(t)
			roots := pool.Roots()
			req.Len(roots, 2)
			req.NotNil(roots[0])
			req.NotNil(roots[1])

			t.Run("adding the same root does not alter roots", func(t *testing.T) {
				req = require.New(t)

				err := pool.AddCa(pki.RootA.cert)

				req.NoError(err)
				req.Len(pool.Roots(), 2)
			})
		})

		t.Run("the pool has 4 intermediates", func(t *testing.T) {
			req = require.New(t)
			intermediates := pool.Intermediates()
			req.Len(intermediates, 4)
			req.NotNil(intermediates[0])
			req.NotNil(intermediates[1])
			req.NotNil(intermediates[2])
			req.NotNil(intermediates[3])

			t.Run("adding the same intermediate does not alter intermediates", func(t *testing.T) {
				req = require.New(t)

				err := pool.AddCa(pki.IntermediateA4.cert)

				req.NoError(err)
				req.Len(pool.Intermediates(), 4)
			})
		})

		t.Run("attempting to add a leaf to the pool results in an error", func(t *testing.T) {
			req = require.New(t)
			req.Error(pool.AddCa(pki.LeafC.cert))
		})

		t.Run("attempting to add nil to the pool results in an error", func(t *testing.T) {
			req = require.New(t)
			req.Error(pool.AddCa(nil))
		})

		t.Run("building a chain minus root from nil results in nil", func(t *testing.T) {
			req = require.New(t)
			req.Nil(pool.GetChainMinusRoot(nil))
		})

		t.Run("building a chain from nil results in nil", func(t *testing.T) {
			req = require.New(t)
			req.Nil(pool.GetChain(nil))
		})

		t.Run("building a chain not from the pool results in just the leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChain(pki.LeafC.cert)

			req.Len(chain, 1)
			req.Equal(pki.LeafC.cert, chain[0])
		})

		t.Run("building a chain minus roots for a cert not in the pool results in just the leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChainMinusRoot(pki.LeafC.cert)

			req.Len(chain, 1)
			req.Equal(pki.LeafC.cert, chain[0])
		})

		t.Run("building a chain minus roots for a leaf signed by a root results in just the leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChainMinusRoot(pki.LeafA.cert)

			req.Len(chain, 1)
			req.Equal(pki.LeafA.cert, chain[0])
		})

		t.Run("building a chain with root for a leaf signed by a root results in the root and leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChain(pki.LeafA.cert)

			req.Len(chain, 2)
			req.Equal(pki.LeafA.cert, chain[0])
			req.Equal(pki.RootA.cert, chain[1])
		})

		t.Run("building a chain minus roots for a leaf signed by a direct intermediates results in intermediate, leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChainMinusRoot(pki.LeafA1.cert)

			req.Len(chain, 2)
			req.Equal(pki.LeafA1.cert, chain[0])
			req.Equal(pki.IntermediateA1.cert, chain[1])
		})

		t.Run("building a chain with root for a leaf signed by a direct intermediate results in root, intermediate, leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChain(pki.LeafA1.cert)

			req.Len(chain, 3)
			req.Equal(pki.LeafA1.cert, chain[0])
			req.Equal(pki.IntermediateA1.cert, chain[1])
			req.Equal(pki.RootA.cert, chain[2])
		})

		t.Run("building a chain minus roots for a leaf signed by a nested intermediates results in intermediate, intermediate, leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChainMinusRoot(pki.LeafA2.cert)

			req.Len(chain, 3)
			req.Equal(pki.LeafA2.cert, chain[0])
			req.Equal(pki.IntermediateA2.cert, chain[1])
			req.Equal(pki.IntermediateA1.cert, chain[2])
		})

		t.Run("building a chain with root for a leaf signed by a nested intermediate results in root, intermediate, intermediate, leaf", func(t *testing.T) {
			req = require.New(t)
			chain := pool.GetChain(pki.LeafA2.cert)

			req.Len(chain, 4)
			req.Equal(pki.LeafA2.cert, chain[0])
			req.Equal(pki.IntermediateA2.cert, chain[1])
			req.Equal(pki.IntermediateA1.cert, chain[2])
			req.Equal(pki.RootA.cert, chain[3])
		})
	})

}

// TestCaPool_IntegrationTests uses identity configuration loading to power CaPool tests
func TestCaPool_IntegrationTests(t *testing.T) {

	t.Run("root -> leaf returns a chain of 1: root", func(t *testing.T) {
		idc := Config{
			Key:  "./testdata/root/keys/client1.key",
			Cert: "./testdata/root/certs/client1.cert",
			CA:   "./testdata/chain.pem",
		}
		req := require.New(t)
		id, err := LoadIdentity(idc)
		req.NoError(err)

		pool := id.CaPool()
		chain := pool.GetChainMinusRoot(id.Cert().Leaf)
		req.Equal(1, len(chain))
		req.Equal("client1", chain[0].Subject.CommonName)
	})

	t.Run("root -> intermediate -> leaf returns a chain of 2: root -> intermediate", func(t *testing.T) {
		idc := Config{
			Key:  "./testdata/ctrl1/keys/client2.key",
			Cert: "./testdata/ctrl1/certs/client2.cert",
			CA:   "./testdata/chain.pem",
		}
		req := require.New(t)
		id, err := LoadIdentity(idc)
		req.NoError(err)

		pool := id.CaPool()
		chain := pool.GetChainMinusRoot(id.Cert().Leaf)
		req.Equal(2, len(chain))
		req.Equal("client2", chain[0].Subject.CommonName)
		req.Equal("ctrl11", chain[1].Subject.CommonName)
	})

	t.Run("root -> intermediate -> intermediate -> leaf returns a chain of 3: root -> intermediate -> intermediate", func(t *testing.T) {
		idc := Config{
			Key:  "./testdata/ctrl2/keys/client3.key",
			Cert: "./testdata/ctrl2/certs/client3.cert",
			CA:   "./testdata/chain.pem",
		}
		req := require.New(t)
		id, err := LoadIdentity(idc)
		req.NoError(err)

		pool := id.CaPool()
		chain := pool.GetChainMinusRoot(id.Cert().Leaf)
		req.Equal(3, len(chain))
		req.Equal("client3", chain[0].Subject.CommonName)
		req.Equal("ctrl2", chain[1].Subject.CommonName)
		req.Equal("ctrl11", chain[2].Subject.CommonName)
	})
}

// testPki is a generated in memory PKI with the following structure:
//
//	 RootA (complex PKI with multiple leafs and intermediates)
//	 |
//	 |-LeafA
//	 |
//	 |-IntermediateA1
//	 | |
//	 | |-LeafA1
//	 | |
//	 | |-IntermediateA2
//	 |   |
//	 |   |-LeafA2
//	 |   |
//	 |   |-IntermediateA3
//	 |     |
//	 |     |-LeafA3
//	 |
//	 |-IntermediateA4
//	   |
//	   |- LeafA4
//
//	RootB (random solo root)
//
//	LeafC (random solo leaf with no CAs)
type testPki struct {
	RootA          *testCa
	LeafA          *certPair
	IntermediateA1 *testCa
	LeafA1         *certPair
	IntermediateA2 *testCa
	LeafA2         *certPair
	IntermediateA3 *testCa
	LeafA3         *certPair
	IntermediateA4 *testCa
	LeafA4         *certPair
	RootB          *testCa
	LeafC          *certPair
}

func newTestPki() *testPki {
	rootA := newRootCa()
	intermediateA1 := rootA.NewIntermediateWithAKID()
	intermediateA2 := intermediateA1.NewIntermediateWithAKID()
	intermediateA3 := intermediateA2.NewIntermediateWithAKID()
	intermediateA4 := rootA.NewIntermediateWithAKID()

	rootB := newRootCa()
	rootC := newRootCa()

	result := &testPki{
		RootA:          rootA,
		LeafA:          rootA.NewLeafWithAKID(),
		IntermediateA1: intermediateA1,
		LeafA1:         intermediateA1.NewLeafWithAKID(),
		IntermediateA2: intermediateA2,
		LeafA2:         intermediateA2.NewLeafWithAKID(),
		IntermediateA3: intermediateA3,
		LeafA3:         intermediateA3.NewLeafWithAKID(),
		IntermediateA4: intermediateA4,
		LeafA4:         intermediateA4.NewLeafWithAKID(),
		RootB:          rootB,
		LeafC:          rootC.NewLeafWithAKID(),
	}

	result.LeafC = rootC.NewLeafWithAKID()

	return result
}

func (t *testPki) Roots() []*x509.Certificate {
	return []*x509.Certificate{
		t.RootA.cert,
		t.RootB.cert,
	}
}

func (t *testPki) Intermediates() []*x509.Certificate {
	return []*x509.Certificate{
		t.IntermediateA1.cert,
		t.IntermediateA2.cert,
		t.IntermediateA3.cert,
		t.IntermediateA4.cert,
	}
}

func (t *testPki) AllCas() []*x509.Certificate {
	cas := t.Roots()
	cas = append(cas, t.Intermediates()...)
	return cas
}
