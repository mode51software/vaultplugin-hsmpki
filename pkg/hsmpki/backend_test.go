package hsmpki

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mode51software/vaultplugin-hsmpki/pkg/pki"
	"testing"
)

type testEnv struct {
	HsmPkiBackend *HsmPkiBackend
	Context       context.Context
	Storage       logical.Storage
	RoleName      string
}

// https://github.com/Venafi/vault-pki-backend-venafi/blob/v0.9.0/plugin/pki/env_test.go#L1787
func newIntegrationTestEnv() (*testEnv, error) {
	ctx := context.Background()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	var err error
	b, err := Backend(config)
	err = b.pkiBackend.Backend.Setup(context.Background(), config)
	if err != nil {
		return nil, err
	}

	return &testEnv{
		HsmPkiBackend: b,
		Context:       ctx,
		Storage:       config.StorageView,
		RoleName:      "testrole",
	}, nil
}

// Set the working directory if TEST_CONFIG_HSM is relative
func TestConnectPkcs11Connection(t *testing.T) {
	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	if err = integraTest.HsmPkiBackend.loadConf(TEST_CONFIG_HSM); err != nil {
		t.Fatal(err)
	}

	integraTest.HsmPkiBackend.configurePkcs11Connection()
	if err = integraTest.HsmPkiBackend.checkPkcs11ConnectionSync(); err != nil {
		t.Fatal("PKCS#11 connection timed out")
	}
}

// populate the /cert/ca_key_alias path with test data
func TestPathSetFetchCAKeyLabel(t *testing.T) {
	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	entry := logical.StorageEntry{}
	entry.Key = PATH_CAKEYALIAS
	entry.Value = []byte("testlabel")

	if err = integraTest.HsmPkiBackend.storeEntry(integraTest.Context, &entry, &integraTest.Storage); err != nil {
		t.Fatal(err)
	}

	testFetchCAKeyLabel(t, integraTest)
}

// by default the key label will be empty so it needs to have been set first
func testFetchCAKeyLabel(t *testing.T, integraTest *testEnv) {

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      PATH_CAKEYALIAS,
		Storage:   integraTest.Storage,
	}

	if resp, err := integraTest.HsmPkiBackend.pathFetchCAKeyAlias(integraTest.Context, req, nil); err != nil {
		t.Error(err)
	} else {
		t.Logf("Key Label: %s", resp.Data[FIELD_KEYALIAS])
	}
}

func TestPathRoleCreate(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testRoleCreate(t, integraTest)
}

// 	vault write hsmpki_int/roles/localhost allowed_domains=localhost allow_subdomains=true max_ttl=72h
func testRoleCreate(t *testing.T, integraTest *testEnv) {

	entry := logical.StorageEntry{}
	entry.Key = PATH_ROLE
	entry.Value = []byte("localhost")

	if err := integraTest.HsmPkiBackend.storeEntry(integraTest.Context, &entry, &integraTest.Storage); err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_ROLE,
		Storage:   integraTest.Storage,
	}

	roles := pki.PathRoles(&integraTest.HsmPkiBackend.pkiBackend.Backend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: roles.Fields,
	}
	data.Raw["name"] = TEST_ROLENAME
	data.Raw["allowed_domains"] = TEST_ALLOWED_DOMAINS
	data.Raw["allow_subdomains"] = true
	data.Raw["max_ttl"] = TEST_MAX_TTL
	data.Raw["ttl"] = TEST_TTL

	if _, err := integraTest.HsmPkiBackend.pkiBackend.Backend.PathRoleCreate(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
		t.Logf("Created role: %s", TEST_ROLENAME)
	}

}

func TestPathSetSignedIntermediate(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testSetSignedIntermediate(t, integraTest)
}

func testSetSignedIntermediate(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_SETSIGNEDINTERMEDIATE,
		Storage:   integraTest.Storage,
	}

	path := pathSetSignedIntermediate(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}
	data.Raw["certificate"] = TEST_SIGNEDCACERTFILE

	if _, err := integraTest.HsmPkiBackend.pathSetSignedIntermediate(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
		t.Logf("Set signed intermediate: %s", TEST_SIGNEDCACERTFILE)
	}
}

func TestPathSetCRLConfig(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testSetCRLConfig(t, integraTest)
}

func testSetCRLConfig(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_SETCRLCONFIG,
		Storage:   integraTest.Storage,
	}

	path := pki.PathConfigCRL(&integraTest.HsmPkiBackend.pkiBackend.Backend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}
	data.Raw["expiry"] = DEFAULT_CRL_LIFETIME

	if _, err := integraTest.HsmPkiBackend.pkiBackend.Backend.PathCRLWrite(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
		t.Logf("Set CRL config: %d", DEFAULT_CRL_LIFETIME)
	}
}

func TestPathFetchCRL(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testSetCRLConfig(t, integraTest)
	testSetSignedIntermediate(t, integraTest)
	testFetchCRL(t, integraTest)
}

func testFetchCRL(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      PATH_FETCHCRL,
		Storage:   integraTest.Storage,
	}

	path := pki.PathFetchCRL(&integraTest.HsmPkiBackend.pkiBackend.Backend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}

	if res, err := integraTest.HsmPkiBackend.pkiBackend.Backend.PathFetchRead(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
		t.Logf("Fetched CRL status where 200 is populated, 204 is empty: %d", res.Data[logical.HTTPStatusCode])
	}
}

/*func init() {

	b, err := newBackend()
	if err != nil {
		panic(err)
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.pkiBackend.Backend.Setup(ctx, conf); err != nil {
		panic(err)
	}

}*/
