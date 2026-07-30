//go:build !js

/*
	Copyright 2019 NetFoundry Inc.

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
	"context"
	"log/slog"

	"github.com/fsnotify/fsnotify"
	"github.com/openziti/foundation/v2/logging"
)

// StopWatchingFiles decrements the number of watchers. If zero is hit all watching is stopped.
// If too many stops are called a panic will occur.
func (id *ID) StopWatchingFiles() {
	if count := id.watchCount.Add(-1); count == 0 {
		close(id.closeNotify)
	} else if count < 0 {
		logging.Panic(context.Background(), "StopWatchingFiles called when not watching",
			slog.String("channel", "identity"), slog.Int("count", int(count)))
	}
}

// WatchFiles will increment the number of watchers. The first watcher will start a
// file system watcher. WatchFiles should match with a StopWatchingFiles.
func (id *ID) WatchFiles() error {
	if id.watchCount.Add(1) == 1 {
		return id.startWatching()
	}

	return nil
}

// startWatching starts an internal file watcher
func (id *ID) startWatching() error {
	id.closeNotify = make(chan struct{})
	files := id.getFiles()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			if closeErr := watcher.Close(); closeErr != nil {
				log.Error("error closing identity file watcher", "error", closeErr)
			}
		}()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					log.Error("identity file watcher received !ok from events, no further information")
					return
				}

				log.Info("identity file watcher received event, queuing reload", "event", event.String())
				id.queueReload(id.closeNotify)

			case err, ok := <-watcher.Errors:
				if err != nil {
					log.Error("identity file watcher received an error", "error", err)
				}

				if !ok {
					log.Error("identity file watcher received !ok from errors, no further information")
					return
				}
			case <-id.closeNotify:
				log.Info("identity file watcher closing")
				return
			}
		}
	}()

	for _, file := range files {
		if err = watcher.Add(file); err != nil {
			_ = watcher.Close()
			return err
		}
	}

	return nil
}
