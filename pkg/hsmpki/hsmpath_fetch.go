package hsmpki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// This returns the currently configured key alias that corresponds to the Intermediate CA's private key in the HSM
func pathFetchCAKeyLabel(b *HsmPkiBackend) *framework.Path {
	return &framework.Path{
		Pattern: PATH_CAKEYLABEL,

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
	return b.loadCAKeyData(ctx, storage, PATH_CAKEYLABEL)
}

func (b *HsmPkiBackend) loadCAKeyType(ctx context.Context, storage logical.Storage) (uint, error) {
	if data, err := b.loadCAKeyData(ctx, storage, PATH_CAKEYTYPE); err != nil {
		b.cachedCAConfig.caKeyType = 0
		return 0, err
	} else {
		val := uint(data.Value[0])
		b.cachedCAConfig.caKeyType = val
		return val, nil
	}
}

func (b *HsmPkiBackend) loadCAKeySize(ctx context.Context, storage logical.Storage) (int, error) {
	if data, err := b.loadCAKeyData(ctx, storage, PATH_CAKEYSIZE); err != nil {
		b.cachedCAConfig.caKeySize = 0
		return 0, err
	} else {
		val := (int(data.Value[0]) * 256) + (int(data.Value[1]))
		b.cachedCAConfig.caKeySize = val
		return val, nil
	}
}

func (b *HsmPkiBackend) loadCAKeyData(ctx context.Context, storage logical.Storage, data string) (*logical.StorageEntry, error) {
	ret, err := storage.Get(ctx, data)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (b *HsmPkiBackend) saveCAKeyData(ctx context.Context, storage logical.Storage,
	caKeyLabel *string, caKeyType uint, caKeySize int) (err error) {
	if err = b.saveCAKeyLabel(ctx, storage, caKeyLabel); err != nil {
		return
	}
	if err = b.saveCAKeyType(ctx, storage, caKeyType); err != nil {
		return
	}
	if err = b.saveCAKeySize(ctx, storage, caKeySize); err != nil {
		return
	}
	return
}

func (b *HsmPkiBackend) saveCAKeyLabel(ctx context.Context, storage logical.Storage, caKeyAlias *string) error {
	data := []byte(*caKeyAlias)
	b.cachedCAConfig.caKeyAlias = *caKeyAlias
	return b.saveStoreData(ctx, storage, PATH_CAKEYLABEL, &data)
}

func (b *HsmPkiBackend) saveCAKeyType(ctx context.Context, storage logical.Storage, caKeyType uint) error {
	data := []byte{byte(caKeyType)}
	b.cachedCAConfig.caKeyType = caKeyType
	return b.saveStoreData(ctx, storage, PATH_CAKEYTYPE, &data)
}

func (b *HsmPkiBackend) saveCAKeySize(ctx context.Context, storage logical.Storage, caKeySize int) error {
	data := []byte{byte(caKeySize / 256), byte(caKeySize % 256)}
	b.cachedCAConfig.caKeySize = caKeySize
	return b.saveStoreData(ctx, storage, PATH_CAKEYSIZE, &data)
}

func (b *HsmPkiBackend) saveStoreData(ctx context.Context, storage logical.Storage, path string, data *[]byte) error {
	entry := logical.StorageEntry{
		Key:      path,
		Value:    *data,
		SealWrap: false,
	}
	if err := storage.Put(ctx, &entry); err != nil {
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
