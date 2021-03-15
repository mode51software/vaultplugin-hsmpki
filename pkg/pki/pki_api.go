package pki

import (
	"context"
	"crypto/x509"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/logical"
	"sync"
	"time"
)

type PkiBackend struct {
	Backend backend
}

func (b *PkiBackend) GetRole(ctx context.Context, s logical.Storage, n string) (*RoleEntry, error) {
	role, err := b.Backend.getRole(ctx, s, n)
	retRole := RoleEntry{role}
	return &retRole, err
}

func AddNonCACommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	return addNonCACommonFields(fields)
}

func AddCACommonFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	return addCACommonFields(fields)
}

func AddCAIssueFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	return addCAIssueFields(fields)
}

func AddCAKeyGenerationFields(fields map[string]*framework.FieldSchema) map[string]*framework.FieldSchema {
	return addCAKeyGenerationFields(fields)
}

func (b *PkiBackend) GetGenerationParams(data *framework.FieldData) (exported bool, format string, role *roleEntry, errorResp *logical.Response) {
	return b.Backend.getGenerationParams(data)
}

func GetFormat(data *framework.FieldData) string {
	return getFormat(data)
}

func FetchCAInfo(ctx context.Context, req *logical.Request) (*certutil.CAInfoBundle, error) {
	return fetchCAInfo(ctx, req)
}

func FetchCertBySerial(ctx context.Context, req *logical.Request, prefix, serial string) (*logical.StorageEntry, error) {
	return fetchCertBySerial(ctx, req, prefix, serial)
}

func ConvertRespToPKCS8(resp *logical.Response) error {
	return convertRespToPKCS8(resp)
}

func NormalizeSerial(serial string) string {
	return normalizeSerial(serial)
}

func BuildCRL(ctx context.Context, b *PkiBackend, req *logical.Request, forceNew bool) error {
	return buildCRL(ctx, &b.Backend, req, forceNew)
}

//func GenerateConvertedCreationBundle(b *backend, data *interface{}, caSign *certutil.CAInfoBundle, csr *x509.CertificateRequest) (*certutil.CreationBundle, error) {
//	dataBundle := (*data).(inputBundle)
//	return GenerateCreationBundle(b, &dataBundle, caSign, csr)
//}

func GenerateConvertedCreationBundle(b *backend, data *InputBundleA, caSign *certutil.CAInfoBundle, csr *x509.CertificateRequest) (*certutil.CreationBundle, error) {
	dataBundle := inputBundle{
		role:    data.Role.roleEntry,
		req:     data.Req,
		apiData: data.ApiData,
	}
	return GenerateCreationBundle(b, &dataBundle, caSign, csr)
}

func GenerateIntermediateCSR(b *backend, data *InputBundleA) (*certutil.ParsedCSRBundle, error) {
	dataBundle := inputBundle{
		role:    data.Role.roleEntry,
		req:     data.Req,
		apiData: data.ApiData,
	}
	return generateIntermediateCSR(b, &dataBundle)
}

func GenerateCreationBundle(b *backend, data *inputBundle, caSign *certutil.CAInfoBundle, csr *x509.CertificateRequest) (*certutil.CreationBundle, error) {
	return generateCreationBundle(b, data, caSign, csr)
}

func GetURLs(ctx context.Context, req *logical.Request) (*certutil.URLEntries, error) {
	return getURLs(ctx, req)
}

func PathListRoles(b *backend) *framework.Path {
	return pathListRoles(b)
}

func PathRoles(b *backend) *framework.Path {
	return pathRoles(b)
}

func (b *backend) PathRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleCreate(ctx, req, data)
}

func PathConfigCRL(b *backend) *framework.Path {
	return pathConfigCRL(b)
}

func (b *backend) PathCRLWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return b.pathCRLWrite(ctx, req, d)
}

func PathFetchCRL(b *backend) *framework.Path {
	return pathFetchCRL(b)
}

func (b *backend) PathFetchRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	return b.pathFetchRead(ctx, req, data)
}

func PathFetchCRLViaCertPath(b *backend) *framework.Path {
	return pathFetchCRLViaCertPath(b)
}

func PathFetchCAChain(b *backend) *framework.Path {
	return pathFetchCAChain(b)
}

//func PathRevoke(b *backend) *framework.Path {
//	return pathRevoke(b)
//}

func PathFetchListCerts(b *backend) *framework.Path {
	return pathFetchListCerts(b)
}

func PathFetchValid(b *backend) *framework.Path {
	return pathFetchValid(b)
}

func PathFetchCA(b *backend) *framework.Path {
	return pathFetchCA(b)
}

func SecretCerts(b *backend) *framework.Secret {
	return secretCerts(b)
}

func (b *PkiBackend) SetCrlLifetime(crlLifetime time.Duration) {
	b.Backend.crlLifetime = crlLifetime
}

func (b *PkiBackend) GetCrlLifetime() time.Duration {
	return b.Backend.crlLifetime
}

func (b *PkiBackend) SetStorage(storage logical.Storage) {
	b.Backend.storage = storage
}

func (b *PkiBackend) GetStorage() logical.Storage {
	return b.Backend.storage
}

func (b *PkiBackend) CreateTidyCASGuard() {
	b.Backend.tidyCASGuard = new(uint32)
}

func (b *PkiBackend) GetTidyCASGuard() *uint32 {
	return b.Backend.tidyCASGuard
}

func (b *PkiBackend) GetRevokeStorageLock() *sync.RWMutex {
	return &b.Backend.revokeStorageLock
}

type RoleEntry struct {
	*roleEntry
}

func GenRoleEntry() *RoleEntry {
	locRoleEntry := roleEntry{}
	retRoleEntry := RoleEntry{&locRoleEntry}
	return &retRoleEntry
}

type InputBundleA struct {
	Role    *RoleEntry
	Req     *logical.Request
	ApiData *framework.FieldData
}

//func (*InputBundleA)

type InputBundleB struct {
	*inputBundle
}
