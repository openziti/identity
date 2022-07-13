package identity

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"testing"
)

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

const (
	TestValueCert       = "./ziti/etc/ca/intermediate/certs/ctrl-client.cert.pem"
	TestValueKey        = "./ziti/etc/ca/intermediate/private/ctrl.key.pem"
	TestValueServerCert = "./ziti/etc/ca/intermediate/certs/ctrl-server.cert.pem"
	TestValueServerKey  = "./ziti/etc/ca/intermediate/certs/ctrl-server.key.pem"
	TestValueCa         = "./ziti/etc/ca/intermediate/certs/ca-chain.cert.pem"

	TestValueAltServerCert01 = "./ziti/etc/ca/intermediate/certs/alt01-ctrl-server.cert.pem"
	TestValueAltServerKey01  = "./ziti/etc/ca/intermediate/certs/alt01-ctrl-server.key.pem"

	TestValueAltServerCert02 = "./ziti/etc/ca/intermediate/certs/alt02-ctrl-server.cert.pem"
	TestValueAltServerKey02  = "./ziti/etc/ca/intermediate/certs/alt02-ctrl-server.key.pem"

	TestValuePathContext = "my.path"

	TestValueMissingOrBlankFieldErrorTemplate = "required configuration value [%s] is missing or is blank"
	TestValueMissingOrBlankFieldsTemplate     = "required configuration values [%s], [%s] are both missing or are blank"
	TestValueMapStringErrorTemplate           = "value [%s] must be a string"

	TestValueJsonNoAltServerCertsTemplate = `
		{
		  "cert": "%s",
		  "key": "%s",
		  "server_cert": "%s",
		  "server_key": "%s",
		  "ca": "%s"
		}`

	TestValueJsonWithAltServerCertsTemplate = `
		{
		  "cert": "%s",
		  "key": "%s",
		  "server_cert": "%s",
		  "server_key": "%s",
		  "ca": "%s",
		  "alt_server_certs": [
            {
              "server_cert": "%s",
              "server_key": "%s"
            },
            {
              "server_cert": "%s",
              "server_key": "%s"
            }
          ]
		}`

	TestValueYamlNoAltServerCertsTemplate = `
cert: "%s"
key: "%s"
server_cert: "%s"
server_key: "%s"
ca: "%s"
`

	TestValueYamlWithAltServerCertsTemplate = `

cert: "%s"
key: "%s"
server_cert: "%s"
server_key: "%s"
ca: "%s"
alt_server_certs:
 - server_cert: "%s"
   server_key: "%s"
 - server_cert: "%s"
   server_key: "%s"
`
)

func Test_Config(t *testing.T) {
	t.Run("can parse from JSON", func(t *testing.T) {
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey,
			TestValueServerCert, TestValueServerKey, TestValueCa))

		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req := require.New(t)
		req.NoError(err)
		req.Equal(TestValueCert, config.Cert)
		req.Equal(TestValueKey, config.Key)
		req.Equal(TestValueServerCert, config.ServerCert)
		req.Equal(TestValueServerKey, config.ServerKey)
		req.Equal(TestValueCa, config.CA)
	})

	t.Run("can parse from JSON with alt server certs", func(t *testing.T) {
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey,
			TestValueServerCert, TestValueServerKey, TestValueCa,
			TestValueAltServerCert01, TestValueAltServerKey01,
			TestValueAltServerCert02, TestValueAltServerKey02))

		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req := require.New(t)
		req.NoError(err)
		req.Equal(TestValueCert, config.Cert)
		req.Equal(TestValueKey, config.Key)
		req.Equal(TestValueServerCert, config.ServerCert)
		req.Equal(TestValueServerKey, config.ServerKey)
		req.Equal(TestValueCa, config.CA)
		req.Equal(TestValueAltServerCert01, config.AltServerCerts[0].ServerCert)
		req.Equal(TestValueAltServerKey01, config.AltServerCerts[0].ServerKey)
		req.Equal(TestValueAltServerCert02, config.AltServerCerts[1].ServerCert)
		req.Equal(TestValueAltServerKey02, config.AltServerCerts[1].ServerKey)
	})

	t.Run("can parse from YAML", func(t *testing.T) {
		identityConfigYaml := []byte(fmt.Sprintf(TestValueYamlNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))

		config := Config{}
		err := yaml.Unmarshal(identityConfigYaml, &config)

		req := require.New(t)
		req.NoError(err)
		req.Equal(TestValueCert, config.Cert)
		req.Equal(TestValueKey, config.Key)
		req.Equal(TestValueServerCert, config.ServerCert)
		req.Equal(TestValueServerKey, config.ServerKey)
		req.Equal(TestValueCa, config.CA)
	})

	t.Run("can parse from YAML with alt server certs", func(t *testing.T) {
		identityConfigYaml := []byte(fmt.Sprintf(TestValueYamlWithAltServerCertsTemplate, TestValueCert, TestValueKey,
			TestValueServerCert, TestValueServerKey, TestValueCa,
			TestValueAltServerCert01, TestValueAltServerKey01,
			TestValueAltServerCert02, TestValueAltServerKey02))

		config := Config{}
		err := yaml.Unmarshal(identityConfigYaml, &config)

		req := require.New(t)
		req.NoError(err)
		req.Equal(TestValueCert, config.Cert)
		req.Equal(TestValueKey, config.Key)
		req.Equal(TestValueServerCert, config.ServerCert)
		req.Equal(TestValueServerKey, config.ServerKey)
		req.Equal(TestValueCa, config.CA)
		req.Equal(TestValueAltServerCert01, config.AltServerCerts[0].ServerCert)
		req.Equal(TestValueAltServerKey01, config.AltServerCerts[0].ServerKey)
		req.Equal(TestValueAltServerCert02, config.AltServerCerts[1].ServerCert)
		req.Equal(TestValueAltServerKey02, config.AltServerCerts[1].ServerKey)
	})
}

func Test_Config_Validate(t *testing.T) {
	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.Validate())
	})

	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.Validate())
	})

	t.Run("empty string cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "cert"), err.Error())
	})

	t.Run("empty string key returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "key"), err.Error())
	})

	t.Run("empty string server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "server_cert"), err.Error())
	})

	t.Run("empty string ca returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, ""))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "ca"), err.Error())
	})

	t.Run("empty string server_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.NoError(err)
	})

	t.Run("empty string alt_server_cert[0].sever_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa,
			TestValueAltServerCert01, "",
			TestValueAltServerCert02, TestValueAltServerKey02))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.NoError(err)
	})

	t.Run("empty string alt_server_cert[0].server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa,
			TestValueAltServerKey02, TestValueAltServerKey01,
			"", TestValueAltServerKey02))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.Validate()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "alt_server_certs[1].server_cert"), err.Error())
	})
}

func Test_Config_ValidateWithPathContext(t *testing.T) {
	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateWithPathContext(TestValuePathContext))
	})

	t.Run("empty string cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".cert"), err.Error())
	})

	t.Run("empty string key returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".key"), err.Error())
	})

	t.Run("empty string server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".server_cert"), err.Error())
	})

	t.Run("empty string ca returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, ""))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".ca"), err.Error())
	})

	t.Run("empty string server_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.NoError(err)
	})

	t.Run("empty string alt_server_cert[0].sever_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa,
			TestValueAltServerCert01, "",
			TestValueAltServerCert02, TestValueAltServerKey02))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.NoError(err)
	})

	t.Run("empty string alt_server_cert[0].server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa,
			TestValueAltServerKey02, TestValueAltServerKey01,
			"", TestValueAltServerKey02))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "my.path.alt_server_certs[1].server_cert"), err.Error())
	})
}

func Test_Config_ValidateForClient(t *testing.T) {
	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForClient())
	})

	t.Run("minimum fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", "", ""))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForClient())
	})

	t.Run("empty string cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClient()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "cert"), err.Error())
	})

	t.Run("empty string key returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClient()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "key"), err.Error())
	})

	t.Run("empty string server_cert returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClient()
		req.NoError(err)
	})

	t.Run("empty string ca returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, ""))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClient()
		req.NoError(err)
	})

	t.Run("empty string server_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClient()
		req.NoError(err)
	})
}

func Test_Config_ValidateForClientWithPathContext(t *testing.T) {

	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForClientWithPathContext(TestValuePathContext))
	})

	t.Run("minimum fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", "", ""))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForClientWithPathContext(TestValuePathContext))
	})

	t.Run("empty string cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClientWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".cert"), err.Error())
	})

	t.Run("empty string key returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClientWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".key"), err.Error())
	})

	t.Run("empty string server_cert returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClientWithPathContext(TestValuePathContext)
		req.NoError(err)
	})

	t.Run("empty string ca returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, ""))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClientWithPathContext(TestValuePathContext)
		req.NoError(err)
	})

	t.Run("empty string server_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForClientWithPathContext(TestValuePathContext)
		req.NoError(err)
	})
}

func Test_Config_ValidateForServer(t *testing.T) {
	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForServer())
	})

	t.Run("minimum fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForServer())
	})

	t.Run("minimum fields present no server_key returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, "", TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForServer())
	})

	t.Run("empty string cert returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.NoError(err)
	})

	t.Run("empty string key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.NoError(err)
	})

	t.Run("empty string server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "server_cert"), err.Error())
	})

	t.Run("empty string ca returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, ""))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "ca"), err.Error())
	})

	t.Run("empty string server_key and no default key returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, "", TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldsTemplate, "key", "server_key"), err.Error())
	})

	t.Run("empty string alt_server_cert[0].sever_key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa,
			TestValueAltServerCert01, "",
			TestValueAltServerCert02, TestValueAltServerKey02))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.NoError(err)
	})

	t.Run("empty string alt_server_cert[0].server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonWithAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, "", TestValueCa,
			TestValueAltServerKey02, TestValueAltServerKey01,
			"", TestValueAltServerKey02))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServer()
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, "alt_server_certs[1].server_cert"), err.Error())
	})
}

func Test_Config_ValidateForServerWithPathContext(t *testing.T) {
	t.Run("all fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForServerWithPathContext(TestValuePathContext))
	})

	t.Run("minimum fields present returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForServerWithPathContext(TestValuePathContext))
	})

	t.Run("minimum fields present no server_key returns no errors", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, "", TestValueCa))
		config := Config{}
		err := json.Unmarshal(identityConfigJson, &config)

		req.NoError(err)
		req.NoError(config.ValidateForServerWithPathContext(TestValuePathContext))
	})

	t.Run("empty string cert returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, "", TestValueKey, TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServerWithPathContext(TestValuePathContext)
		req.NoError(err)
	})

	t.Run("empty string key returns no error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServerWithPathContext(TestValuePathContext)
		req.NoError(err)
	})

	t.Run("empty string server_cert returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, "", TestValueServerKey, TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServerWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".server_cert"), err.Error())
	})

	t.Run("empty string ca returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, TestValueKey, TestValueServerCert, TestValueServerKey, ""))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServerWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldErrorTemplate, TestValuePathContext+".ca"), err.Error())
	})

	t.Run("empty string server_key and no default key returns error", func(t *testing.T) {
		req := require.New(t)
		identityConfigJson := []byte(fmt.Sprintf(TestValueJsonNoAltServerCertsTemplate, TestValueCert, "", TestValueServerCert, "", TestValueCa))
		config := Config{}

		err := json.Unmarshal(identityConfigJson, &config)
		req.NoError(err)

		err = config.ValidateForServerWithPathContext(TestValuePathContext)
		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMissingOrBlankFieldsTemplate, TestValuePathContext+".key", TestValuePathContext+".server_key"), err.Error())
	})
}

func Test_NewConfigFromMap(t *testing.T) {
	t.Run("can parse all values from a map", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		config, err := NewConfigFromMap(configMap)

		req.NoError(err)
		req.Equal(TestValueCert, config.Cert)
		req.Equal(TestValueKey, config.Key)
		req.Equal(TestValueServerCert, config.ServerCert)
		req.Equal(TestValueServerKey, config.ServerKey)
		req.Equal(TestValueCa, config.CA)
	})

	t.Run("errors on non-string cert", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        1,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMap(configMap)

		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMapStringErrorTemplate, "cert"), err.Error())
	})

	t.Run("errors on non-string key", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         1,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMap(configMap)

		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMapStringErrorTemplate, "key"), err.Error())
	})

	t.Run("errors on non-string server_cert", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": 1,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMap(configMap)

		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMapStringErrorTemplate, "server_cert"), err.Error())
	})

	t.Run("errors on non-string server_key", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  1,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMap(configMap)

		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMapStringErrorTemplate, "server_key"), err.Error())
	})

	t.Run("errors on non-string ca", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          1,
		}

		_, err := NewConfigFromMap(configMap)

		req.Error(err)
		req.Equal(fmt.Sprintf(TestValueMapStringErrorTemplate, "ca"), err.Error())
	})
}

func Test_NewConfigFromMapWithPathContext(t *testing.T) {
	t.Run("can parse all values from a map", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		config, err := NewConfigFromMapWithPathContext(configMap, TestValuePathContext)

		req.NoError(err)
		req.Equal(config.Cert, TestValueCert)
		req.Equal(config.Key, TestValueKey)
		req.Equal(config.ServerCert, TestValueServerCert)
		req.Equal(config.ServerKey, TestValueServerKey)
		req.Equal(config.CA, TestValueCa)
	})

	t.Run("errors on non-string cert", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        1,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMapWithPathContext(configMap, TestValuePathContext)

		req.Error(err)
		req.Equal(err.Error(), fmt.Sprintf(TestValueMapStringErrorTemplate, TestValuePathContext+".cert"))
	})

	t.Run("errors on non-string key", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         1,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMapWithPathContext(configMap, TestValuePathContext)

		req.Error(err)
		req.Equal(err.Error(), fmt.Sprintf(TestValueMapStringErrorTemplate, TestValuePathContext+".key"))
	})

	t.Run("errors on non-string server_cert", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": 1,
			"server_key":  TestValueServerKey,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMapWithPathContext(configMap, TestValuePathContext)

		req.Error(err)
		req.Equal(err.Error(), fmt.Sprintf(TestValueMapStringErrorTemplate, TestValuePathContext+".server_cert"))
	})

	t.Run("errors on non-string server_key", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  1,
			"ca":          TestValueCa,
		}

		_, err := NewConfigFromMapWithPathContext(configMap, TestValuePathContext)

		req.Error(err)
		req.Equal(err.Error(), fmt.Sprintf(TestValueMapStringErrorTemplate, TestValuePathContext+".server_key"))
	})

	t.Run("errors on non-string ca", func(t *testing.T) {
		req := require.New(t)

		configMap := map[interface{}]interface{}{
			"cert":        TestValueCert,
			"key":         TestValueKey,
			"server_cert": TestValueServerCert,
			"server_key":  TestValueServerKey,
			"ca":          1,
		}

		_, err := NewConfigFromMapWithPathContext(configMap, TestValuePathContext)

		req.Error(err)
		req.Equal(err.Error(), fmt.Sprintf(TestValueMapStringErrorTemplate, TestValuePathContext+".ca"))
	})
}
