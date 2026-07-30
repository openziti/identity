//go:build engines
// +build engines

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
	"os"
	"path/filepath"
	"plugin"
	"sync"

	"github.com/openziti/foundation/v2/logging"
)

var supportedEngines = []string{
	"siometrics.so",
	"authenta.so",
}

var log = logging.For("identity.certtools")

var loaded = false
var loadMu = sync.Mutex{}

func loadEngines() {
	if loaded {
		return
	}

	loadMu.Lock()
	defer loadMu.Unlock()

	if loaded {
		return
	}

	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	log.Debug("resolved executable dir", "dir", execDir)

	for _, lib := range supportedEngines {
		libPath := filepath.Join(execDir, lib)
		log.Debug("trying engine lib", "path", libPath)
		l, err := plugin.Open(libPath)

		if err != nil {
			log.Debug("failed to load engine", "path", libPath, "error", err)
			continue
		}

		e, err := l.Lookup("Engine")
		if err != nil {
			log.Warn("symbol 'Engine' not found", "lib", lib, "path", libPath)
			continue
		}

		if engine, ok := e.(Engine); ok {
			log.Debug("found engine", "engine", engine.Id(), "lib", lib, "path", libPath)
			engines[engine.Id()] = engine
		} else {
			log.Warn("engine instance is not valid", "lib", lib)
			continue
		}
	}

	loaded = true
}
