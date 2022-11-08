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
	"github.com/stretchr/testify/require"
	"testing"
)

func TestID_CaPoolGetChainDirectChild(t *testing.T) {
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
}

func TestID_CaPoolGetChainChildOnceRemoved(t *testing.T) {
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
}

func TestID_CaPoolGetChainChildTwiceRemoved(t *testing.T) {
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
}
