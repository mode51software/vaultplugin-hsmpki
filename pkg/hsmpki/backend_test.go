package hsmpki

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mode51software/pkcs11helper/pkg/pkcs11client"
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

	/*	if err = integraTest.HsmPkiBackend.loadConf(TEST_CONFIG_HSM); err != nil {
			t.Fatal(err)
		}

		integraTest.HsmPkiBackend.configurePkcs11Connection()
		if err = integraTest.HsmPkiBackend.checkPkcs11ConnectionSync(); err != nil {
			t.Fatal("PKCS#11 connection timed out")
		}*/
	testConnectPkcs11Connection(t, integraTest)

}

func testConnectPkcs11Connection(t *testing.T, integraTest *testEnv) {

	if err := integraTest.HsmPkiBackend.loadConf(TEST_CONFIG_HSM); err != nil {
		t.Fatal(err)
	}

	integraTest.HsmPkiBackend.configurePkcs11Connection()
	if err := integraTest.HsmPkiBackend.checkPkcs11ConnectionSync(); err != nil {
		t.Fatal("PKCS#11 connection timed out")
	}
}

// populate the /cert/ca_keylabel path with test data
func TestPathSetFetchCAKeyLabel(t *testing.T) {
	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	entry := logical.StorageEntry{}
	entry.Key = PATH_CAKEYLABEL
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
		Path:      PATH_CAKEYLABEL,
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

	testConnectPkcs11Connection(t, integraTest)
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

	if caData, err := pkcs11client.LoadFromFileAsString(TEST_SIGNEDCACERTFILE); err != nil {
		t.Error(err)
		return
	} else {
		data.Raw["certificate"] = caData
	}
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

	testConnectPkcs11Connection(t, integraTest)
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

func TestPathRevokeCRL(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testSetCRLConfig(t, integraTest)
	testSetSignedIntermediate(t, integraTest)
	testFetchCRL(t, integraTest)
	testRevokeCRL(t, integraTest)
}

func testRevokeCRL(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_REVOKE,
		Storage:   integraTest.Storage,
	}

	path := pathRevoke(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}

	if _, err := integraTest.HsmPkiBackend.pathRevokeWrite(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
	}
}

func TestPathTidyCRL(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testSetCRLConfig(t, integraTest)
	testSetSignedIntermediate(t, integraTest)
	testFetchCRL(t, integraTest)
	testRevokeCRL(t, integraTest)
	testTidyCRL(t, integraTest)
}

func testTidyCRL(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_REVOKE,
		Storage:   integraTest.Storage,
	}

	path := pathRevoke(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}

	if _, err := integraTest.HsmPkiBackend.pathRevokeWrite(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
	}
}

func TestRotateCRL(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testSetCRLConfig(t, integraTest)
	testSetSignedIntermediate(t, integraTest)
	testFetchCRL(t, integraTest)
	testRevokeCRL(t, integraTest)
	testRotateCRL(t, integraTest)
}

func testRotateCRL(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_ROTATECRL,
		Storage:   integraTest.Storage,
	}

	path := pathRotateCRL(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}

	if _, err := integraTest.HsmPkiBackend.pathRotateCRLRead(integraTest.Context, req, &data); err != nil {
		t.Error(err)
	} else {
	}
}

func TestPathGenerateRoot(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testGenerateRoot(t, integraTest)
}

func testGenerateRoot(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_GENERATEROOT,
		Storage:   integraTest.Storage,
	}

	path := pathGenerateRoot(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}
	data.Raw[FIELD_COMMON_NAME] = TEST_CAROOTCOMMONNAME
	data.Raw[FIELD_EXPORTED] = TEST_EXPORTED
	data.Raw[FIELD_KEY_TYPE] = TEST_CAKEYTYPERSA
	data.Raw[FIELD_KEY_BITS] = TEST_CAKEYBITSRSA
	//	data.Raw[FIELD_PERMITTED_DNS_NAMES] = TEST_CAPERMITTEDDNSDOMAINS
	data.Raw[FIELD_ORGANIZATION] = TEST_CAORGANIZATION
	data.Raw[FIELD_OU] = TEST_CAOU
	data.Raw[FIELD_COUNTRY] = TEST_CACOUNTRY
	data.Raw[FIELD_LOCALITY] = TEST_CALOCALITY
	data.Raw[FIELD_STREET_ADDRESS] = TEST_CASTREETADDRESS
	data.Raw[FIELD_PROVINCE] = TEST_CAPROVINCE
	data.Raw[FIELD_STREET_ADDRESS] = TEST_CASTREETADDRESS
	data.Raw[FIELD_POSTAL_CODE] = TEST_CAPOSTALCODE
	data.Raw[FIELD_TTL] = TEST_CATTL

	//caKeyAlias := "ECTestCARootKey0017"
	//integraTest.HsmPkiBackend.saveCAKeyAlias(context.Background(), integraTest.Storage, &caKeyAlias)
	//integraTest.HsmPkiBackend.cachedCAConfig.caKeyAlias = caKeyAlias

	if response, err := integraTest.HsmPkiBackend.pathCAGenerateRoot(integraTest.Context, req, &data); err != nil || response.Error() != nil {
		if err != nil {
			t.Error(err)
		} else if response.Error() != nil {
			t.Error(response.Error())
		}
	} else {
		strData := response.Data[FIELD_CERTIFICATE].(string)
		byteData := []byte(strData)
		pkcs11client.SaveDataToFile(TEST_ROOTCACERTFILE, &byteData)
		t.Logf("Generate Root succeeded key label is: %s data: %s", response.Data[FIELD_KEYALIAS], response.Data[FIELD_CERTIFICATE])
	}
}

// creates a new CSR for a new or existing HSM key
func TestPathGenerateIntermediate(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testGenerateIntermediate(t, integraTest)
}

func testGenerateIntermediate(t *testing.T, integraTest *testEnv) string {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_GENERATEINTERMEDIATE,
		Storage:   integraTest.Storage,
	}

	path := pathGenerateIntermediate(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}
	data.Raw[FIELD_COMMON_NAME] = TEST_CAINTERCOMMONNAME
	data.Raw[FIELD_EXPORTED] = TEST_EXPORTED
	data.Raw[FIELD_KEY_TYPE] = TEST_CAKEYTYPEEC
	data.Raw[FIELD_KEY_BITS] = TEST_CAKEYBITSEC
	//	data.Raw[FIELD_PERMITTED_DNS_NAMES] = TEST_CAPERMITTEDDNSDOMAINS
	data.Raw[FIELD_ORGANIZATION] = TEST_CAORGANIZATION
	data.Raw[FIELD_OU] = TEST_CAOU
	data.Raw[FIELD_COUNTRY] = TEST_CACOUNTRY
	data.Raw[FIELD_LOCALITY] = TEST_CALOCALITY
	data.Raw[FIELD_STREET_ADDRESS] = TEST_CASTREETADDRESS
	data.Raw[FIELD_PROVINCE] = TEST_CAPROVINCE
	data.Raw[FIELD_STREET_ADDRESS] = TEST_CASTREETADDRESS
	data.Raw[FIELD_POSTAL_CODE] = TEST_CAPOSTALCODE
	data.Raw[FIELD_TTL] = TEST_CATTL

	caKeyAlias := "ECTestCARootKey0017"

	//integraTest.HsmPkiBackend.saveCAKeyAlias(context.Background(), integraTest.Storage, &caKeyAlias)
	integraTest.HsmPkiBackend.cachedCAConfig.caKeyAlias = caKeyAlias

	if response, err := integraTest.HsmPkiBackend.pathGenerateIntermediate(integraTest.Context, req, &data); err != nil || response.Error() != nil {
		if err != nil {
			t.Error(err)
		} else if response.Error() != nil {
			t.Error(response.Error())
		}
		return ""
	} else {
		t.Logf("Generate Intermediate succeeded: %s", response.Data["csr"])
		strData := response.Data["csr"].(string)
		byteData := []byte(strData)
		// for use as input into TestPathSignIntermediate
		pkcs11client.SaveDataToFile(TEST_INTERCSRFILE, &byteData)
		return strData
	}

}

/*
// sign intermediate needs a CSR as input that is to be signed with the RootCA
// usually Generate Root will be run on mount path A, then Generate Intermediate on mount path B,
// then Sign Intermediate on mount path A, followed by Set Signed Intermediate on mount path B
func TestPathSignIntermediate(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)

	rootCACert, err := pkcs11client.LoadFromFileAsString(TEST_ROOTCACERTFILE)
	cb := &certutil.CertBundle{}
	cb.Certificate = *rootCACert

	entry, err := logical.StorageEntryJSON(CA_BUNDLE, cb)
	if err != nil {
		t.Error(err)
		return
	}
	err = integraTest.Storage.Put(context.Background(), entry)

	if csr, err := pkcs11client.LoadFromFileAsString(TEST_INTERCSRFILE); err != nil {
		t.Error(err)
	} else {
		testSignIntermediate(t, integraTest, csr)
	}
}

func testSignIntermediate(t *testing.T, integraTest *testEnv, csr *string) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_SIGNINTERMEDIATE,
		Storage:   integraTest.Storage,
	}

	path := pathSignIntermediate(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}
	data.Raw[FIELD_COMMON_NAME] = TEST_CAINTERCOMMONNAME
	data.Raw[FIELD_EXPORTED] = TEST_EXPORTED
	data.Raw[FIELD_KEY_TYPE] = TEST_CAKEYTYPEEC
	data.Raw[FIELD_KEY_BITS] = TEST_CAKEYBITSEC
	//	data.Raw[FIELD_PERMITTED_DNS_NAMES] = TEST_CAPERMITTEDDNSDOMAINS
	data.Raw[FIELD_ORGANIZATION] = TEST_CAORGANIZATION
	data.Raw[FIELD_OU] = []string{TEST_CAOU}
	data.Raw[FIELD_COUNTRY] = TEST_CACOUNTRY
	data.Raw[FIELD_LOCALITY] = TEST_CALOCALITY
	data.Raw[FIELD_STREET_ADDRESS] = TEST_CASTREETADDRESS
	data.Raw[FIELD_PROVINCE] = TEST_CAPROVINCE
	data.Raw[FIELD_STREET_ADDRESS] = TEST_CASTREETADDRESS
	data.Raw[FIELD_POSTAL_CODE] = TEST_CAPOSTALCODE
	data.Raw[FIELD_TTL] = TEST_CATTL
	data.Raw[FIELD_CSR] = *csr

	caKeyAlias := "ECTestCARootKey0017"

	//integraTest.HsmPkiBackend.saveCAKeyAlias(context.Background(), integraTest.Storage, &caKeyAlias)
	integraTest.HsmPkiBackend.cachedCAConfig.caKeyAlias = caKeyAlias

	if response, err := integraTest.HsmPkiBackend.pathCASignIntermediate(integraTest.Context, req, &data); err != nil || response.Error() != nil {
		if err != nil {
			t.Error(err)
		} else if response.Error() != nil {
			t.Error(response.Error())
		}
	} else {
		strData := response.Data[FIELD_CERTIFICATE].(string)
		byteData := []byte(strData)
		// for use as input into TestSetSignedIntermediate
		pkcs11client.SaveDataToFile(TEST_INTERCERTFILE, &byteData)
		t.Logf("Sign Intermediate succeeded: %s", response.Data[FIELD_CERTIFICATE])
	}
}

func TestPathIssue(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testRoleCreate(t, integraTest)
	testSetSignedIntermediate(t, integraTest)

	bundleEntry, err := integraTest.Storage.Get(context.Background(), CA_BUNDLE)
	var bundle certutil.CertBundle
	if err = bundleEntry.DecodeJSON(&bundle); err != nil {
		return //, errutil.InternalError{Err: fmt.Sprintf("unable to decode local CA certificate/key: %v", err)}
	}
	t.Logf("bundle=%s", bundle.Certificate)

	testIssue(t, integraTest)
}

func testIssue(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      PATH_ISSUE,
		Storage:   integraTest.Storage,
	}

	path := pathIssue(integraTest.HsmPkiBackend)

	data := framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: path.Fields,
	}

	data.Raw[FIELD_ROLE] = TEST_ROLE_NAME
	data.Raw[FIELD_COMMON_NAME] = TEST_COMMON_NAME

	//caKeyAlias := "ECTestCARootKey0017"

	//integraTest.HsmPkiBackend.saveCAKeyAlias(context.Background(), integraTest.Storage, &caKeyAlias)
	//integraTest.HsmPkiBackend.cachedCAConfig.caKeyAlias = caKeyAlias

	if response, err := integraTest.HsmPkiBackend.pathIssue(integraTest.Context, req, &data); err != nil || response.Error() != nil {
		if err != nil {
			t.Error(err)
		} else if response.Error() != nil {
			t.Error(response.Error())
		}
	} else {
		t.Logf("Issue succeeded: %s", response.Data["certificate"])
	}
}
*/
func TestPathDeleteRoot(t *testing.T) {

	integraTest, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	testConnectPkcs11Connection(t, integraTest)
	testGenerateRoot(t, integraTest)
	testDeleteRoot(t, integraTest)
}

func testDeleteRoot(t *testing.T, integraTest *testEnv) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      PATH_ROOT,
		Storage:   integraTest.Storage,
	}
	if response, err := integraTest.HsmPkiBackend.pathCADeleteRoot(integraTest.Context, req, nil); err != nil || response.Error() != nil {
		if err != nil {
			t.Error(err)
		} else if response.Error() != nil {
			t.Error(response.Error())
		}
	} else {
		t.Logf("Delete CA succeeded: %s", integraTest.HsmPkiBackend.cachedCAConfig.caKeyAlias)
	}

}
