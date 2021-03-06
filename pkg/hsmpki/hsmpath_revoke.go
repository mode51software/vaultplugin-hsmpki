package hsmpki

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRevoke(b *HsmPkiBackend) *framework.Path {
	return &framework.Path{
		Pattern: PATH_REVOKE,
		Fields: map[string]*framework.FieldSchema{
			"serial_number": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Certificate serial number, in colon- or
hyphen-separated octal`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRevokeWrite,
		},

		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

func pathRotateCRL(b *HsmPkiBackend) *framework.Path {
	return &framework.Path{
		Pattern: PATH_ROTATECRL,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathRotateCRLRead,
		},

		HelpSynopsis:    pathRotateCRLHelpSyn,
		HelpDescription: pathRotateCRLHelpDesc,
	}
}

func (b *HsmPkiBackend) pathRevokeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if err := b.checkPkcs11ConnectionSync(); err != nil {
		return nil, err
	}

	serial := data.Get("serial_number").(string)
	if len(serial) == 0 {
		return logical.ErrorResponse("The serial number must be provided"), nil
	}

	if b.pkiBackend.Backend.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	// We store and identify by lowercase colon-separated hex, but other
	// utilities use dashes and/or uppercase, so normalize
	serial = strings.Replace(strings.ToLower(serial), "-", ":", -1)

	b.pkiBackend.GetRevokeStorageLock().Lock()
	defer b.pkiBackend.GetRevokeStorageLock().Unlock()

	return revokeCert(ctx, b, req, serial, false)
}

func (b *HsmPkiBackend) pathRotateCRLRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if err := b.checkPkcs11ConnectionSync(); err != nil {
		return nil, err
	}

	b.pkiBackend.GetRevokeStorageLock().RLock()
	defer b.pkiBackend.GetRevokeStorageLock().RUnlock()

	crlErr := buildCRL(ctx, b, req, false)
	switch crlErr.(type) {
	case errutil.UserError:
		return logical.ErrorResponse(fmt.Sprintf("Error during CRL building: %s", crlErr)), nil
	case errutil.InternalError:
		return nil, errwrap.Wrapf("error encountered during CRL building: {{err}}", crlErr)
	default:
		return &logical.Response{
			Data: map[string]interface{}{
				"success": true,
			},
		}, nil
	}
}

const pathRevokeHelpSyn = `
Revoke a certificate by serial number.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoked using its serial number. A root token is required.
`

const pathRotateCRLHelpSyn = `
Force a rebuild of the CRL.
`

const pathRotateCRLHelpDesc = `
Force a rebuild of the CRL. This can be used to remove expired certificates from it if no certificates have been revoked. A root token is required.
`
