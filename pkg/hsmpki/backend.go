package hsmpki

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mode51software/pkcs11helper/pkg/pkcs11client"
	"github.com/mode51software/vaultplugin-hsmpki/pkg/pki"
	"io/ioutil"
	"strings"
	"sync"
	"time"
)

type cachedCAConfig struct {
	caKeyAlias string
	hashAlgo   crypto.Hash
}

type HsmPkiBackend struct {
	pkiBackend     pki.PkiBackend
	HsmBackend     *framework.Backend
	pkcs11client   pkcs11client.Pkcs11Client
	cachedCAConfig cachedCAConfig // needs to be re-cached on startup
	refreshMutex   sync.Mutex
	store          map[string][]byte
	connChannel    chan int
	backendConfig  *logical.BackendConfig

	// this is the same storage as in the pki Backend, so ref here for convenience
	//storage        logical.Storage
}

var _ logical.Factory = Factory

// Factory configures and returns backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err = b.pkiBackend.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}
	b.backendConfig = conf
	if _, ok := conf.Config[CONFIG_PARAM]; !ok {
		b.pkiBackend.Backend.Logger().Error("Please add a parameter specifying a file containing the HSM's configuration. Plugin mounting aborted.")
	}
	return b.pkiBackend.Backend, nil

}

// plugins are launched first in metadata mode then lazily loaded later so don't create the connection until fully loaded
// https://groups.google.com/g/vault-tool/c/z6iaU_B159A/m/ag7OJaeECQAJ
func (b *HsmPkiBackend) initnow(ctx context.Context, req *logical.InitializationRequest) error {
	b.pkiBackend.Backend.Logger().Info("Init")

	if confFile, ok := b.backendConfig.Config[CONFIG_PARAM]; ok {

		b.pkiBackend.Backend.Logger().Info("found conf: " + confFile)

		// check the conf is valid
		if err := b.loadConf(confFile); err != nil {
			return errwrap.Wrapf("Conf file error: {{err}}", err)
		}

		b.loadStorage()
		b.configurePkcs11Connection()
		b.checkPkcs11ConnectionAsync()

	} else {
		b.pkiBackend.Backend.Logger().Error("Please add a parameter specifying a file containing the HSM's configuration. Plugin mounting aborted.")
		return errors.New("Please add a parameter specifying a file containing the HSM's configuration. Plugin mounting aborted.")
	}

	return nil
}

func Backend(conf *logical.BackendConfig) (*HsmPkiBackend, error) {
	b := &HsmPkiBackend{
		store: make(map[string][]byte),
	}

	b.pkiBackend.Backend.Backend = &framework.Backend{
		Help:           strings.TrimSpace(PLUGIN_HELP),
		BackendType:    logical.TypeLogical,
		InitializeFunc: b.initnow,
		Paths: []*framework.Path{
			pki.PathListRoles(&b.pkiBackend.Backend),
			pki.PathRoles(&b.pkiBackend.Backend),
			pathGenerateRoot(b),
			pathSignIntermediate(b),
			//pathSignSelfIssued(&b),
			pathDeleteRoot(b),
			pathGenerateIntermediate(b),
			pathSetSignedIntermediate(b),
			//pathConfigCA(&b),	// not implemented
			pki.PathConfigCRL(&b.pkiBackend.Backend),
			pki.PathConfigURLs(&b.pkiBackend.Backend),
			//pathSignVerbatim(&b),
			pathSign(b),
			pathIssue(b),
			pathRotateCRL(b),
			pki.PathFetchCA(&b.pkiBackend.Backend),
			pki.PathFetchCAChain(&b.pkiBackend.Backend),
			pki.PathFetchCRL(&b.pkiBackend.Backend),
			pki.PathFetchCRLViaCertPath(&b.pkiBackend.Backend),
			pki.PathFetchValid(&b.pkiBackend.Backend),
			pki.PathFetchListCerts(&b.pkiBackend.Backend),
			pathRevoke(b),
			pathTidy(b),
			pathFetchCAKeyLabel(b), // new path
		},
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"cert/*",
				"ca/pem",
				"ca_chain",
				"ca",
				"crl/pem",
				"crl",
			},

			LocalStorage: []string{
				"revoked/",
				"crl",
				"certs/",
			},

			SealWrapStorage: []string{
				"config/ca_bundle",
			},
		},

		Secrets: []*framework.Secret{
			pki.SecretCerts(&b.pkiBackend.Backend),
		},
	}
	b.pkiBackend.SetCrlLifetime(time.Hour * DEFAULT_CRL_LIFETIME)
	b.pkiBackend.SetStorage(conf.StorageView)
	b.pkiBackend.CreateTidyCASGuard()

	return b, nil
}

func (b *HsmPkiBackend) configurePkcs11Connection() {
	b.pkcs11client.HsmConfig.CheckSetDefaultTimeouts()
}

// on startup attempt to connect asynchronously
func (b *HsmPkiBackend) checkPkcs11ConnectionAsync() {

	b.connChannel = make(chan int)

	go func() {
		//for {

		b.pkiBackend.Backend.Logger().Info("Checking PKCS#11 connection")

		// plugins are launched first in metadata mode then lazily loaded later so don't create the connection until fully loaded
		// https://groups.google.com/g/vault-tool/c/z6iaU_B159A/m/ag7OJaeECQAJ
		timer := time.NewTimer(time.Second * 3)
		select {
		case <-b.connChannel:
			b.pkiBackend.Backend.Logger().Info("Shutting down PKCS#11 connection monitor")
			return
		case <-timer.C:
			// continue
			b.checkPkcs11ConnectionSync()
		}
		//}
	}()
	return
}

func (b *HsmPkiBackend) checkPkcs11ConnectionFailed() {
	b.refreshMutex.Lock()
	defer b.refreshMutex.Unlock()

	if b.pkcs11client.ConnectionState != pkcs11client.PKCS11CONNECTION_INPROGRESS &&
		b.pkcs11client.ConnectionState != pkcs11client.PKCS11CONNECTION_SUCCEEDED {
		b.pkcs11client.Pkcs11Mutex.Lock()
		b.pkcs11client.FlushSession()
		b.pkcs11client.Pkcs11Mutex.Unlock()
		//b.checkPkcs11ConnectionAsync()
	}
}

// Synchronously check the PKCS#11 connection
func (b *HsmPkiBackend) checkPkcs11ConnectionSync() (err error) {

	b.refreshMutex.Lock()
	defer b.refreshMutex.Unlock()

	if b.pkcs11client.ConnectionState != pkcs11client.PKCS11CONNECTION_SUCCEEDED &&
		b.pkcs11client.ConnectionState != pkcs11client.PKCS11CONNECTION_INPROGRESS {

		b.pkiBackend.Backend.Logger().Info("Attempt to connect PKCS#11 connection")

		if err = b.pkcs11client.InitAndLoginWithTimeout(); err != nil {
			b.pkiBackend.Backend.Logger().Info("PKCS#11 connection error")
		} else {
			b.pkiBackend.Backend.Logger().Info("PKCS#11 connection successful")
		}
	}
	return
}

// conf params stored in the conf file that is specified when the secrets engine is enabled
func (b *HsmPkiBackend) loadConf(filename string) error {

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	tree, err := hcl.ParseBytes(data)
	if err != nil {
		return err
	}

	var hsmPkiConfig HsmPkiConfig
	if err = hcl.DecodeObject(&hsmPkiConfig, tree.Node); err != nil {
		b.pkiBackend.Backend.Logger().Error(err.Error())
		return err
	}

	// the local version of HsmConfig is needed because hcl needs different annotations and doesn't parse uints (?)
	b.pkcs11client.HsmConfig = hsmPkiConfig.ConvertToHsmConfig()

	if err = b.pkcs11client.HsmConfig.ValidateConfig(); err != nil {
		//	if err = b.hsmPkiConfig.validateConfig(); err != nil {
		return err
	} else {
		msg := fmt.Sprintf("Loaded conf file lib %s slot %d label %s",
			b.pkcs11client.HsmConfig.Lib, b.pkcs11client.HsmConfig.SlotId, b.pkcs11client.HsmConfig.KeyLabel)
		b.pkiBackend.Backend.Logger().Info(msg)
		b.pkcs11client.HsmConfig.CheckSetDefaultTimeouts()
		return nil
	}
}

// conf items that can be set dynamically
// load in the key label override if it has been set during Set Signed Intermediate
func (b *HsmPkiBackend) loadStorage() {

	caKeyAlias, err := b.loadCAKeyAlias(context.Background(), b.pkiBackend.GetStorage())
	if err != nil || caKeyAlias == nil || caKeyAlias.Value == nil {
		msg := fmt.Sprintf("No HSM key label in storage, use conf file: %s", b.pkcs11client.HsmConfig.KeyLabel)
		b.pkiBackend.Backend.Logger().Info(msg)
		// no override, use the conf file's key label (if set)
		b.cachedCAConfig.caKeyAlias = b.pkcs11client.HsmConfig.KeyLabel
	} else {
		msg := fmt.Sprintf("Found HSM key label in storage: %s", caKeyAlias.Value)
		b.pkiBackend.Backend.Logger().Info(msg)
	}

}
