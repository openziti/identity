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

package certtools

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// Shake256HexN returns a SHAKE256 hash of "length" bytes as a hex string (2*length = count of hex characters).
func Shake256HexN(data []byte, length int) string {
	hash := make([]byte, length)
	hasher := sha3.NewShake256()
	hasher.Write(data)
	hasher.Read(hash)
	return hex.EncodeToString(hash)
}
