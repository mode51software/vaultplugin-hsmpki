package hsmpki

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mode51software/vaultplugin-hsmpki/pkg/pki"
	"time"
)

func pathIssue(b *HsmPkiBackend) *framework.Path {
	ret := &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathIssue,
		},

		HelpSynopsis:    pathIssueHelpSyn,
		HelpDescription: pathIssueHelpDesc,
	}

	ret.Fields = pki.AddNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func pathSign(b *HsmPkiBackend) *framework.Path {
	ret := &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSign,
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}

	ret.Fields = pki.AddNonCACommonFields(map[string]*framework.FieldSchema{})

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
	}

	return ret
}

// pathIssue issues a certificate and private key from given parameters,
// subject to role restrictions
func (b *HsmPkiBackend) pathIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.pkiBackend.GetRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	if role.KeyType == "any" {
		return logical.ErrorResponse("role key type \"any\" not allowed for issuing certificates, only signing"), nil
	}

	return b.pathIssueSignCert(ctx, req, data, role, false, false)
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *HsmPkiBackend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.pkiBackend.GetRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	return b.pathIssueSignCert(ctx, req, data, role, true, false)
}

func (b *HsmPkiBackend) pathIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role *pki.RoleEntry, useCSR, useCSRValues bool) (*logical.Response, error) {

	b.checkPkcs11ConnectionSync()

	// If storing the certificate and on a performance standby, forward this request on to the primary
	if !role.NoStore && b.pkiBackend.Backend.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	format := pki.GetFormat(data)
	if format == "" {
		return logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", or "pem_bundle"`), nil
	}

	var caErr error
	signingBundle, caErr := pki.FetchCAInfo(ctx, req)
	switch caErr.(type) {
	case errutil.UserError:
		return nil, errutil.UserError{Err: fmt.Sprintf(
			"could not fetch the CA certificate (was one set?): %s", caErr)}
	case errutil.InternalError:
		return nil, errutil.InternalError{Err: fmt.Sprintf(
			"error fetching CA certificate: %s", caErr)}
	}

	input := &pki.InputBundleA{
		Req:     req,
		ApiData: data,
		Role:    role,
	}

	var parsedBundle *certutil.ParsedCertBundle
	var err error

	if useCSR {
		b.pkiBackend.Backend.Logger().Info("do signCert")
		parsedBundle, err = signCert(b, input, signingBundle, false, useCSRValues)
	} else {
		// TODO: generateCert with entropy aug
		parsedBundle, err = generateCert(ctx, b, input, signingBundle, false)
	}
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		default:
			return nil, errwrap.Wrapf("error signing/generating certificate: {{err}}", err)
		}
	}

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw signing bundle to cert bundle: {{err}}", err)
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw cert bundle to cert bundle: {{err}}", err)
	}

	respData := map[string]interface{}{
		"expiration":    int64(parsedBundle.Certificate.NotAfter.Unix()),
		"serial_number": cb.SerialNumber,
	}

	switch format {
	case "pem":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.Certificate
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			respData["ca_chain"] = cb.CAChain
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "pem_bundle":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.ToPEMBundle()
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			respData["ca_chain"] = cb.CAChain
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "der":
		respData["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		respData["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)

		var caChain []string
		for _, caCert := range parsedBundle.CAChain {
			caChain = append(caChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
		}
		if caChain != nil && len(caChain) > 0 {
			respData["ca_chain"] = caChain
		}

		if !useCSR {
			respData["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
			respData["private_key_type"] = cb.PrivateKeyType
		}
	}

	var resp *logical.Response
	switch {
	case role.GenerateLease == nil:
		return nil, fmt.Errorf("generate lease in role is nil")
	case *role.GenerateLease == false:
		// If lease generation is disabled do not populate `Secret` field in
		// the response
		resp = &logical.Response{
			Data: respData,
		}
	default:

		resp = b.HsmBackend.Secret(pki.SecretCertsType).Response(
			respData,
			map[string]interface{}{
				"serial_number": cb.SerialNumber,
			})
		resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())

	}

	if data.Get("private_key_format").(string) == "pkcs8" {
		err = pki.ConvertRespToPKCS8(resp)
		if err != nil {
			return nil, err
		}
	}

	if !role.NoStore {
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   "certs/" + pki.NormalizeSerial(cb.SerialNumber),
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, errwrap.Wrapf("unable to store certificate locally: {{err}}", err)
		}
	}

	if useCSR {
		if role.UseCSRCommonName && data.Get("common_name").(string) != "" {
			resp.AddWarning("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true")
		}
		if role.UseCSRSANs && data.Get("alt_names").(string) != "" {
			resp.AddWarning("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true")
		}
	}

	return resp, nil
}

const pathIssueHelpSyn = `
Request a certificate using a certain role with the provided details.
`

const pathIssueHelpDesc = `
This path allows requesting a certificate to be issued according to the
policy of the given role. The certificate will only be issued if the
requested details are allowed by the role policy.

This path returns a certificate and a private key. If you want a workflow
that does not expose a private key, generate a CSR locally and use the
sign path instead.
`

const pathSignHelpSyn = `
Request certificates using a certain role with the provided details.
`

const pathSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.

This path requires a CSR; if you want Vault to generate a private key
for you, use the issue path instead.
`
