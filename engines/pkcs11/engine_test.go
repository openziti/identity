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

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"github.com/openziti/identity/engines"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net/url"
	_ "net/url"
	"os"
	"os/exec"
	"testing"
)

const pin = "2171"
const softHsmEnvVar = "SOFTHSM2_LIB"

func init() {
	_ = os.Setenv("SOFTHSM2_CONF", "softhsm2.conf")
}

func genTestData(pin string) error {
	err := exec.Command(initScript, getPkcs11Lib(), pin).Run()
	if err != nil {
		return err
	}
	return nil
}

type ecdsaSig struct {
	R, S *big.Int
}

func Test_softhsm2_keys(t *testing.T) {
	pkcs11Lib := getPkcs11Lib()
	eng, found := engines.GetEngine(EngineId)

	if !found {
		t.Logf("skipping %s: enfgine[%s] not found", t.Name(), EngineId)
		t.SkipNow()
	}

	if _, err := os.Stat(pkcs11Lib); err != nil {
		t.Logf("skipping %s: driver not found", t.Name())
		t.SkipNow()
	}

	assert.NoError(t, genTestData(pin))

	keys := map[string]string{
		"prime256v1": "02",
		"rsa:2048":   "01",
	}

	for n, id := range keys {
		t.Logf("testing key %s", n)

		k, err := url.Parse("pkcs11:" + pkcs11Lib + "?pin=" + pin + "&id=" + id)
		if err != nil {
			t.Error(err)
		}

		key, err := eng.LoadKey(k)
		if err != nil {
			t.Error(err)
		} else {
			testSigner(key, t)
		}
	}
}

func testSigner(key crypto.PrivateKey, t *testing.T) {
	privateKey, ok := key.(crypto.Signer)
	if !ok {
		t.Error("key is not a crypto.Signer")
	}

	pub := privateKey.Public()

	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)

	sig, err := privateKey.Sign(rand.Reader, bytes, crypto.SHA256)
	if err != nil {
		t.Error(err)
	}

	switch pubKey := pub.(type) {
	case *ecdsa.PublicKey:
		var ecSig ecdsaSig
		rest, err := asn1.Unmarshal(sig, &ecSig)
		if err != nil {
			t.Error(err)
		}
		if len(rest) != 0 {
			t.Errorf("leftover bytes")
		}

		cool := ecdsa.Verify(pubKey, bytes, ecSig.R, ecSig.S)
		if !cool {
			t.Errorf("signature validation fail")
		}

	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, bytes, sig)
		if err != nil {
			t.Error(err.Error())
		}

	default:
		t.Errorf("bad pub key")
	}
}
