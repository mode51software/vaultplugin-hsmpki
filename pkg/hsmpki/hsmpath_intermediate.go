package hsmpki

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mode51software/vaultplugin-hsmpki/pkg/pki"
	"strings"
)

func pathGenerateIntermediate(b *HsmPkiBackend) *framework.Path {
	ret := &framework.Path{
		Pattern: "intermediate/generate/" + framework.GenericNameRegex("exported"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathGenerateIntermediate,
		},

		HelpSynopsis:    pathGenerateIntermediateHelpSyn,
		HelpDescription: pathGenerateIntermediateHelpDesc,
	}

	ret.Fields = pki.AddCACommonFields(map[string]*framework.FieldSchema{})
	ret.Fields = pki.AddCAKeyGenerationFields(ret.Fields)
	ret.Fields["add_basic_constraints"] = &framework.FieldSchema{
		Type: framework.TypeBool,
		Description: `Whether to add a Basic Constraints
extension with CA: true. Only needed as a
workaround in some compatibility scenarios
with Active Directory Certificate Services.`,
	}

	return ret
}

func pathSetSignedIntermediate(b *HsmPkiBackend) *framework.Path {
	ret := &framework.Path{
		Pattern: PATH_SETSIGNEDINTERMEDIATE,

		Fields: map[string]*framework.FieldSchema{
			"certificate": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `PEM-format certificate. This must be a CA
certificate with a public key and a key alias that matches a private key in the HSM. 
.`,
			},
			"key_label": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The key label of the private key in the HSM.
Providing this will override the key alias that can be set in the configuration file.
.`,
			},
			"hash_algo": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The hash algorithm to use.
For RSA and ECDSA the options are SHA-256, SHA-384 or SHA-512.
.`,
			},
			"verify": &framework.FieldSchema{
				Type: framework.TypeBool,
				Description: `Check that an HSM object exists with the configured key alias.
.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathSetSignedIntermediate,
		},

		HelpSynopsis:    pathSetSignedIntermediateHelpSyn,
		HelpDescription: pathSetSignedIntermediateHelpDesc,
	}

	return ret
}

func (b *HsmPkiBackend) pathGenerateIntermediate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	if err = b.checkPkcs11ConnectionSync(); err != nil {
		return nil, err
	}

	exported, format, role, errorResp := b.getGenerationParams(data)
	if errorResp != nil {
		return errorResp, nil
	}

	var resp *logical.Response
	input := &pki.InputBundleA{
		Role:    role,
		Req:     req,
		ApiData: data,
	}
	parsedBundle, err := generateIntermediateCSR(b, input)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return logical.ErrorResponse(err.Error()), nil
		default:
			return nil, err
		}
	}

	csrb, err := parsedBundle.ToCSRBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw CSR bundle to CSR bundle: {{err}}", err)
	}

	resp = &logical.Response{
		Data: map[string]interface{}{},
	}

	switch format {
	case "pem":
		resp.Data["csr"] = csrb.CSR
		if exported {
			resp.Data["private_key"] = csrb.PrivateKey
			resp.Data["private_key_type"] = csrb.PrivateKeyType
		}

	case "pem_bundle":
		resp.Data["csr"] = csrb.CSR
		if exported {
			resp.Data["csr"] = fmt.Sprintf("%s\n%s", csrb.PrivateKey, csrb.CSR)
			resp.Data["private_key"] = csrb.PrivateKey
			resp.Data["private_key_type"] = csrb.PrivateKeyType
		}

	case "der":
		resp.Data["csr"] = base64.StdEncoding.EncodeToString(parsedBundle.CSRBytes)
		if exported {
			resp.Data["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
			resp.Data["private_key_type"] = csrb.PrivateKeyType
		}
	}

	resp.Data[FIELD_KEYALIAS] = b.cachedCAConfig.caKeyAlias

	/*	if data.Get("private_key_format").(string) == "pkcs8" {
			err = convertRespToPKCS8(resp)
			if err != nil {
				return nil, err
			}
		}
	*/
	cb := &certutil.CertBundle{}
	//	cb.PrivateKey = csrb.PrivateKey
	//	cb.PrivateKeyType = csrb.PrivateKeyType

	entry, err := logical.StorageEntryJSON(CA_BUNDLE, cb)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *HsmPkiBackend) pathSetSignedIntermediate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	b.checkPkcs11ConnectionSync()

	cert := data.Get("certificate").(string)

	if cert == "" {
		return logical.ErrorResponse("no certificate provided in the \"certificate\" parameter"), nil
	}

	inputBundle, err := certutil.ParsePEMBundle(cert)
	if err != nil {
		switch err.(type) {
		case errutil.InternalError:
			return nil, err
		default:
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	if inputBundle.Certificate == nil {
		return logical.ErrorResponse("supplied certificate could not be successfully parsed"), nil
	}

	// HSM the certBundle will now be empty because the Intermediate CA hasn't been generated using Vault

	cb := &certutil.CertBundle{}

	// no local private key

	if !inputBundle.Certificate.IsCA {
		return logical.ErrorResponse("the given certificate is not marked for CA use and cannot be used with this backend"), nil
	}

	if err := inputBundle.Verify(); err != nil {
		return nil, errwrap.Wrapf("verification of parsed bundle failed: {{err}}", err)
	}

	cb, err = inputBundle.ToCertBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw values into cert bundle: {{err}}", err)
	}

	entry, err := logical.StorageEntryJSON(CA_BUNDLE, cb)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	entry.Key = PATH_CERTS + pki.NormalizeSerial(cb.SerialNumber)
	entry.Value = inputBundle.CertificateBytes
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	// For ease of later use, also store just the certificate at a known
	// location
	entry.Key = PATH_CA
	entry.Value = inputBundle.CertificateBytes
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	inCaKeyAlias := data.Get(FIELD_KEYALIAS).(string)
	entry.Key = PATH_CAKEYLABEL

	if inCaKeyAlias == "" {
		// if a key alias has already been set by an auto generated CA cert then can skip
		if len(b.cachedCAConfig.caKeyAlias) == 0 {
			// use the key label provided in the conf file
			entry.Value = []byte(b.pkcs11client.HsmConfig.KeyLabel)
			if err = b.storeEntry(ctx, entry, &req.Storage); err != nil {
				return nil, err
			}
			if len(b.pkcs11client.HsmConfig.KeyLabel) == 0 {
				return nil, errwrap.Wrapf("Either set a key_label in the plugin's conf file or pass in an HSM key label using key_label", nil)
			}
			b.cachedCAConfig.caKeyAlias = b.pkcs11client.HsmConfig.KeyLabel
		}
	} else {

		entry.Value = []byte(inCaKeyAlias)
		if err = b.storeEntry(ctx, entry, &req.Storage); err != nil {
			return nil, err
		}
		b.cachedCAConfig.caKeyAlias = inCaKeyAlias
	}

	inHashAlgo := data.Get(FIELD_HASHALGO).(string)
	var hashAlgoId crypto.Hash
	if inHashAlgo != "" {
		ucHashAlgo := strings.ToUpper(inHashAlgo)
		switch ucHashAlgo {
		case "SHA-256":
			hashAlgoId = crypto.SHA256
		case "SHA-384":
			hashAlgoId = crypto.SHA384
		case "SHA-512":
			hashAlgoId = crypto.SHA512
		default:
			hashAlgoId = 0
		}
	}
	entry.Key = PATH_HASHALGO
	hashAlgoByte := make([]byte, 1)
	hashAlgoByte[0] = byte(hashAlgoId)
	entry.Value = hashAlgoByte
	if err = b.storeEntry(ctx, entry, &req.Storage); err != nil {
		return nil, err
	}
	b.cachedCAConfig.hashAlgo = hashAlgoId

	// TODO: Build a fresh CRL
	err = buildCRL(ctx, b, req, true)

	return nil, err
}

func (b *HsmPkiBackend) storeEntry(ctx context.Context, entry *logical.StorageEntry, storage *logical.Storage) error {
	if err := (*storage).Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

const pathGenerateIntermediateHelpSyn = `
Generate a new CSR and private key used for signing.
`

const pathGenerateIntermediateHelpDesc = `
See the API documentation for more information.
`

const pathSetSignedIntermediateHelpSyn = `
Provide the signed intermediate CA cert.
`

const pathSetSignedIntermediateHelpDesc = `
See the API documentation for more information.
`
