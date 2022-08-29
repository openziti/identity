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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/openziti/foundation/v2/tlz"
	"github.com/openziti/identity/certtools"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	StorageFile = "file"
	StoragePem  = "pem"
)

type Identity interface {
	Cert() *tls.Certificate
	ServerCert() []*tls.Certificate
	CA() *x509.CertPool
	ServerTLSConfig() *tls.Config
	ClientTLSConfig() *tls.Config
	Reload() error

	WatchFiles() error
	StopWatchingFiles()

	SetCert(pem string) error
	SetServerCert(pem string) error

	GetConfig() *Config
}

var _ Identity = &ID{}

type ID struct {
	Config

	certLock sync.RWMutex

	cert       *tls.Certificate
	serverCert []*tls.Certificate
	ca         *x509.CertPool

	needsReload atomic.Bool
	reloader    sync.Once
	watcher     sync.Once
	closeNotify chan struct{}
	watchCount  atomic.Int32
}

// SetCert persists a new PEM as the ID's client certificate.
func (id *ID) SetCert(pem string) error {
	if certUrl, err := parseAddr(id.Config.Cert); err != nil {
		return err
	} else {
		switch certUrl.Scheme {
		case StoragePem:
			id.Config.Cert = StoragePem + ":" + pem
			return fmt.Errorf("could not save client certificate, location scheme not supported for saving (%s):\n%s", id.Config.Cert, pem)
		case StorageFile, "":
			f, err := os.OpenFile(id.Config.Cert, os.O_RDWR, 0664)
			if err != nil {
				return fmt.Errorf("could not update client certificate [%s]: %v", id.Config.Cert, err)
			}

			defer func() { _ = f.Close() }()

			err = f.Truncate(0)

			if err != nil {
				return fmt.Errorf("could not truncate client certificate [%s]: %v", id.Config.Cert, err)
			}

			_, err = fmt.Fprint(f, pem)

			if err != nil {
				return fmt.Errorf("error writing new client certificate [%s]: %v", id.Config.Cert, err)
			}
		default:
			return fmt.Errorf("could not save client certificate, location scheme not supported (%s) or address not defined (%s):\n%s", certUrl.Scheme, id.Config.Cert, pem)
		}
	}

	return nil
}

// SetServerCert persists a new PEM as the ID's server certificate.
func (id *ID) SetServerCert(pem string) error {
	if certUrl, err := parseAddr(id.Config.ServerCert); err != nil {
		return err
	} else {
		switch certUrl.Scheme {
		case StoragePem:
			id.Config.ServerCert = StoragePem + ":" + pem
			return fmt.Errorf("could not save client certificate, location scheme not supported for saving (%s): \n %s", id.Config.Cert, pem)
		case StorageFile, "":
			f, err := os.OpenFile(id.Config.ServerCert, os.O_RDWR, 0664)
			if err != nil {
				return fmt.Errorf("could not update server certificate [%s]: %v", id.Config.ServerCert, err)
			}

			defer func() { _ = f.Close() }()

			err = f.Truncate(0)

			if err != nil {
				return fmt.Errorf("could not truncate server certificate [%s]: %v", id.Config.ServerCert, err)
			}

			_, err = fmt.Fprint(f, pem)

			if err != nil {
				return fmt.Errorf("error writing new server certificate [%s]: %v", id.Config.ServerCert, err)
			}
		default:
			return fmt.Errorf("could not save server certificate, location scheme not supported (%s) or address not defined (%s):\n%s", certUrl.Scheme, id.Config.ServerCert, pem)
		}
	}

	return nil
}

// Reload re-interprets the internal Config that was used to create this ID. This instance of the
// ID is updated with new client, server, and ca configuration. All tls.Config's generated
// from this ID will use the newly loaded values for new connections.
func (id *ID) Reload() error {
	id.certLock.Lock()
	defer id.certLock.Unlock()

	newId, err := LoadIdentity(id.Config)

	if err != nil {
		return fmt.Errorf("failed to reload identity: %v", err)
	}

	id.ca = newId.CA()
	id.cert = newId.Cert()
	id.serverCert = newId.ServerCert()

	return nil
}

// getFiles returns all configuration paths that point to files
func (id *ID) getFiles() []string {
	var files []string
	if path, ok := IsFile(id.Config.Cert); ok {
		files = append(files, path)
	}

	if path, ok := IsFile(id.Config.ServerCert); ok {
		files = append(files, path)
	}

	if path, ok := IsFile(id.Config.Key); ok {
		files = append(files, path)
	}

	if path, ok := IsFile(id.Config.ServerKey); ok {
		files = append(files, path)
	}

	for _, altServerCert := range id.Config.AltServerCerts {
		if path, ok := IsFile(altServerCert.ServerKey); ok {
			files = append(files, path)
		}

		if path, ok := IsFile(altServerCert.ServerCert); ok {
			files = append(files, path)
		}

	}

	return files
}

// StopWatchingFiles decrements the number of watchers. If zero is hit all watching is stopped.
// If too many stops are called a panic will occur.
func (id *ID) StopWatchingFiles() {
	if count := id.watchCount.Add(-1); count == 0 {
		close(id.closeNotify)
	} else if count < 0 {
		logrus.Panicf("StopWatchingFiles called when not watching count is %d", count)
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
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					logrus.Error("identity file watcher received !ok from events, no further information")
					return
				}

				logrus.Info("identity file watcher received event, queuing reload: " + event.String())
				id.queueReload(id.closeNotify)

			case err, ok := <-watcher.Errors:
				if err != nil {
					logrus.Errorf("identity file watcher received an error [%v]", err)
				}

				if !ok {
					logrus.Error("identity file watcher received !ok from errors, no further information")
					return
				}
			case <-id.closeNotify:
				logrus.Info("identity file watcher closing")
				return
			}
		}
	}()

	for _, file := range files {
		err := watcher.Add(file)

		if err != nil {
			_ = watcher.Close()
			close(id.closeNotify)
		}
	}

	return nil
}

// Cert returns the ID's current client certificate that is used by all tls.Config's generated from it.
func (id *ID) Cert() *tls.Certificate {
	id.certLock.RLock()
	defer id.certLock.RUnlock()

	return id.cert
}

// ServerCert returns the ID's current server certificate that is used by all tls.Config's generated from it.
func (id *ID) ServerCert() []*tls.Certificate {
	id.certLock.RLock()
	defer id.certLock.RUnlock()

	return id.serverCert
}

// CA returns the ID's current CA certificate pool that is used by all tls.Config's generated from it.
func (id *ID) CA() *x509.CertPool {
	id.certLock.RLock()
	defer id.certLock.RUnlock()

	return id.ca
}

// ServerTLSConfig returns a new tls.Config instance that will delegate server certificate lookup to the current ID.
// Calling Reload on the source ID will update which server certificate is used if the internal Config is altered
// by calling Config or if the values the Config points to are altered (i.e. file update).
//
// Generating multiple tls.Config's by calling this method will return tls.Config's that are all tied to this ID's
// Config.
func (id *ID) ServerTLSConfig() *tls.Config {
	if id.serverCert == nil {
		return nil
	}

	tlsConfig := &tls.Config{
		GetCertificate: id.GetServerCertificate,
		RootCAs:        id.ca,
		ClientAuth:     tls.RequireAnyClientCert,
		MinVersion:     tlz.GetMinTlsVersion(),
		CipherSuites:   tlz.GetCipherSuites(),
	}

	//for servers, CAs can be updated for new connections by intercepting
	//on new client connections via GetConfigForClient
	tlsConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		return id.GetConfigForClient(tlsConfig, info)
	}

	return tlsConfig
}

// ClientTLSConfig returns a new tls.Config instance that will delegate client certificate lookup to the current ID.
// Calling Reload on the source ID can update which client certificate is used if the internal Config is altered
// by calling Config or if the values the Config points to are altered (i.e. file update).
//
// Generating multiple tls.Config's by calling this method will return tls.Config's that are all tied to this ID's
// Config and client certificates.
func (id *ID) ClientTLSConfig() *tls.Config {
	tlsConfig := &tls.Config{
		RootCAs: id.ca,
	}

	tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return id.GetClientCertificate(tlsConfig, info)
	}

	return tlsConfig
}

// GetServerCertificate is used to satisfy tls.Config's GetCertificate requirements.
// Allows server certificates to be updated after enrollment extensions without stopping
// listeners and disconnecting clients. New settings are used for all new incoming connection.
func (id *ID) GetServerCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	id.certLock.RLock()
	defer id.certLock.RUnlock()

	if len(id.serverCert) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	if len(id.serverCert) == 1 {
		return id.serverCert[0], nil
	}

	for _, cert := range id.serverCert {

		if err := hello.SupportsCertificate(cert); err == nil {
			return cert, nil
		}
	}

	return id.serverCert[0], nil
}

// GetClientCertificate is used to satisfy tls.Config's GetClientCertificate requirements.
// Allows client certificates to be updated after enrollment extensions without disconnecting
// the current client. New settings will be used on re-connect.
func (id *ID) GetClientCertificate(config *tls.Config, _ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	id.certLock.RLock()
	defer id.certLock.RUnlock()

	//root cas updated here because during the client connection process on the client side
	//tls.Config.GetConfigForClient is not called
	config.RootCAs = id.ca

	return id.cert, nil
}

// GetConfig returns the internally stored copy of the Config that was used to create
// the ID. The returned Config can be used to create additional IDs but those IDs
// will not share the same Config.
func (id *ID) GetConfig() *Config {
	return &id.Config
}

// GetConfigForClient is used to satisfy tls.Config's GetConfigForClient requirements.
// Allows servers to have up-to-date CA chains after enrollment extension.
func (id *ID) GetConfigForClient(config *tls.Config, _ *tls.ClientHelloInfo) (*tls.Config, error) {
	config.RootCAs = id.ca
	return config, nil
}

// queueReload de-duplicates reload attempts within a 5s window.
func (id *ID) queueReload(closeNotify <-chan struct{}) {
	id.needsReload.Store(true)
	id.reloader.Do(func() {
		go func() {
			for {
				select {
				case <-time.After(1 * time.Second):
					if needsReload := id.needsReload.CompareAndSwap(true, false); needsReload {
						logrus.Info("reloading identity configuration")
						if err := id.Reload(); err != nil {
							logrus.Errorf("could not reload identity configuration: %v", err)
						}
					}
				case <-closeNotify:
					return
				}
			}
		}()
	})
}

func LoadIdentity(cfg Config) (Identity, error) {
	id := &ID{
		Config: cfg,
		cert:   &tls.Certificate{},
	}

	var err error
	id.cert.PrivateKey, err = LoadKey(cfg.Key)
	if err != nil {
		return nil, err
	}

	if idCert, err := loadCert(cfg.Cert); err != nil {
		return id, err
	} else {
		id.cert.Certificate = make([][]byte, len(idCert))
		for i, c := range idCert {
			id.cert.Certificate[i] = c.Raw
		}
		id.cert.Leaf = idCert[0]
	}

	// Server Cert is optional
	if cfg.ServerCert != "" {
		if svrCert, err := loadCert(cfg.ServerCert); err != nil {
			return id, err
		} else {
			serverKey := id.cert.PrivateKey
			if cfg.ServerKey != "" {
				serverKey, err = LoadKey(cfg.ServerKey)
				if err != nil {
					return nil, err
				}
			}

			chains, err := AssembleServerChains(svrCert)

			if err != nil {
				return nil, err
			}

			tlsCerts := ChainsToTlsCerts(chains, serverKey)
			id.serverCert = append(id.serverCert, tlsCerts...)
		}
	}

	// Alt Server Cert is optional
	for _, altCert := range cfg.AltServerCerts {
		if svrCert, err := loadCert(altCert.ServerCert); err != nil {
			return id, err
		} else {
			serverKey := id.cert.PrivateKey
			if altCert.ServerKey != "" {
				serverKey, err = LoadKey(altCert.ServerKey)
				if err != nil {
					return nil, err
				}
			}

			chains, err := AssembleServerChains(svrCert)

			if err != nil {
				return nil, err
			}

			tlsCerts := ChainsToTlsCerts(chains, serverKey)
			id.serverCert = append(id.serverCert, tlsCerts...)
		}
	}

	// CA bundle is optional
	if cfg.CA != "" {
		if id.ca, err = loadCABundle(cfg.CA); err != nil {
			return id, err
		}
	}

	return id, nil
}

func LoadKey(keyAddr string) (crypto.PrivateKey, error) {
	if keyUrl, err := parseAddr(keyAddr); err != nil {
		return nil, err
	} else {

		switch keyUrl.Scheme {
		case StoragePem:
			return certtools.LoadPrivateKey([]byte(keyUrl.Opaque))
		case StorageFile, "":
			return certtools.GetKey(nil, keyUrl.Path, "")
		default:
			// engine key format: "{engine_id}:{engine_opts} see specific engine for supported options
			return certtools.GetKey(keyUrl, "", "")
			//return nil, fmt.Errorf("could not load key, location scheme not supported (%s) or address not defined (%s)", keyUrl.Scheme, keyAddr)
		}
	}
}

func loadCert(certAddr string) ([]*x509.Certificate, error) {
	if certUrl, err := parseAddr(certAddr); err != nil {
		return nil, err
	} else {
		switch certUrl.Scheme {
		case StoragePem:
			return certtools.LoadCert([]byte(certUrl.Opaque))
		case StorageFile, "":
			return certtools.LoadCertFromFile(certUrl.Path)
		default:
			return nil, fmt.Errorf("could not load cert, location scheme not supported (%s) or address not defined (%s)", certUrl.Scheme, certAddr)
		}
	}
}

// IsFile returns a file path from a given configuration value and true if the configuration value is a file. Otherwise
// returns empty string and false.
func IsFile(configValue string) (string, bool) {
	if certUrl, err := parseAddr(configValue); err != nil {
		return "", false
	} else if certUrl.Scheme == StorageFile {
		return certUrl.Path, true
	}

	return "", false
}

func loadCABundle(caAddr string) (*x509.CertPool, error) {
	if caUrl, err := parseAddr(caAddr); err != nil {
		return nil, err
	} else {
		pool := x509.NewCertPool()
		var bundle []byte
		switch caUrl.Scheme {
		case StoragePem:
			bundle = []byte(caUrl.Opaque)

		case StorageFile, "":
			if bundle, err = ioutil.ReadFile(caUrl.Path); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("NO valid Cert location specified")
		}
		pool.AppendCertsFromPEM(bundle)
		return pool, nil
	}
}
