package hsmpki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// This returns the currently configured key alias that corresponds to the Intermediate CA's private key in the HSM
func pathFetchCAKeyAlias(b *HsmPkiBackend) *framework.Path {
	return &framework.Path{
		Pattern: PATH_CAKEYALIAS,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathFetchCAKeyAlias,
		},

		HelpSynopsis:    pathFetchCAKeyAliasHelpSyn,
		HelpDescription: pathFetchCAKeyAliasHelpDesc,
	}
}

func (b *HsmPkiBackend) pathFetchCAKeyAlias(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	caKeyAlias, err := b.loadCAKeyAlias(ctx, req.Storage) //)req.Storage.Get(ctx, PATH_CAKEYALIAS)
	if err != nil {
		return nil, err
	}

	if caKeyAlias != nil || len(b.pkcs11client.HsmConfig.KeyLabel) > 0 {
		response = &logical.Response{
			Data: map[string]interface{}{},
		}
		if caKeyAlias == nil || caKeyAlias.Value == nil {
			response.Data[FIELD_KEYALIAS] = b.pkcs11client.HsmConfig.KeyLabel
		} else {
			response.Data[FIELD_KEYALIAS] = string(caKeyAlias.Value)
		}
	} else {
		return nil, fmt.Errorf("Unable to read ca key alias")
	}
	return
}

func (b *HsmPkiBackend) loadCAKeyAlias(ctx context.Context, storage logical.Storage) (*logical.StorageEntry, error) {
	caKeyAlias, err := storage.Get(ctx, PATH_CAKEYALIAS)
	if err != nil {
		return nil, err
	}
	return caKeyAlias, nil
}

func (b *HsmPkiBackend) saveCAKeyAlias(ctx context.Context, storage logical.Storage, caKeyAlias *string) error {
	cb := &certutil.CertBundle{}
	entry, err := logical.StorageEntryJSON("config/ca_bundle", cb)
	if err != nil {
		return err
	}
	entry.Key = PATH_CAKEYALIAS
	entry.Value = []byte(*caKeyAlias)
	if err := storage.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

const pathFetchCAKeyAliasHelpSyn = `
Fetch the currently configured CA's key alias
`

const pathFetchCAKeyAliasHelpDesc = `
This allows the correct identification of the key pair on the HSM.
`
