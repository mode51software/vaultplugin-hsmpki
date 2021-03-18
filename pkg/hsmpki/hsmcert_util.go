package hsmpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mode51software/vaultplugin-hsmpki/pkg/pki"
)

type inputBundle struct {
	role    *pki.RoleEntry
	req     *logical.Request
	apiData *framework.FieldData
}

// Fetches the CA info. Unlike other certificates, the CA info is stored
// in the backend as a CertBundle, because we are storing its private key
func fetchCAInfo(ctx context.Context, req *logical.Request) (*certutil.CAInfoBundle, error) {
	bundleEntry, err := req.Storage.Get(ctx, CA_BUNDLE)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch local CA certificate/key: %v", err)}
	}
	if bundleEntry == nil {
		return nil, errutil.UserError{Err: "backend must be configured with a CA certificate/key"}
	}

	var bundle certutil.CertBundle
	if err := bundleEntry.DecodeJSON(&bundle); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to decode local CA certificate/key: %v", err)}
	}

	parsedBundle, err := bundle.ToParsedCertBundle()
	if err != nil {
		return nil, errutil.InternalError{Err: err.Error()}
	}

	if parsedBundle.Certificate == nil {
		return nil, errutil.InternalError{Err: "stored CA information not able to be parsed"}
	}

	caInfo := &certutil.CAInfoBundle{*parsedBundle, nil}

	entries, err := pki.GetURLs(ctx, req)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch URL information: %v", err)}
	}
	if entries == nil {
		entries = &certutil.URLEntries{
			IssuingCertificates:   []string{},
			CRLDistributionPoints: []string{},
			OCSPServers:           []string{},
		}
	}
	caInfo.URLs = entries

	return caInfo, nil
}

// N.B.: This is only meant to be used for generating intermediate CAs.
// It skips some sanity checks.
func generateIntermediateCSR(b *HsmPkiBackend, input *pki.InputBundleA) (*certutil.ParsedCSRBundle, error) {
	creation, err := pki.GenerateConvertedCreationBundle(&b.pkiBackend.Backend, input, nil, nil)
	if err != nil {
		return nil, err
	}
	if creation.Params == nil {
		return nil, errutil.InternalError{Err: "nil parameters received from parameter bundle generation"}
	}

	addBasicConstraints := input.ApiData != nil && input.ApiData.Get("add_basic_constraints").(bool)
	parsedBundle, err := CreateCSR(b, creation, addBasicConstraints)
	if err != nil {
		return nil, err
	}

	return parsedBundle, nil
}

func signCert(b *HsmPkiBackend,
	data *pki.InputBundleA,
	caSign *certutil.CAInfoBundle,
	isCA bool,
	useCSRValues bool) (*certutil.ParsedCertBundle, error) {

	if data.Role == nil {
		return nil, errutil.InternalError{Err: "no role found in data bundle"}
	}

	csrString := data.ApiData.Get("csr").(string)
	if csrString == "" {
		return nil, errutil.UserError{Err: fmt.Sprintf("\"csr\" is empty")}
	}

	pemBytes := []byte(csrString)
	pemBlock, pemBytes := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errutil.UserError{Err: "csr contains no data"}
	}
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, errutil.UserError{Err: fmt.Sprintf("certificate request could not be parsed: %v", err)}
	}

	switch data.Role.KeyType {
	case "rsa":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.RSA {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				data.Role.KeyType)}
		}
		pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errutil.UserError{Err: "could not parse CSR's public key"}
		}

		// Verify that the key is at least 2048 bits
		if pubKey.N.BitLen() < 2048 {
			return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
		}

		// Verify that the bit size is at least the size specified in the role
		if pubKey.N.BitLen() < data.Role.KeyBits {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires a minimum of a %d-bit key, but CSR's key is %d bits",
				data.Role.KeyBits,
				pubKey.N.BitLen())}
		}

	case "ec":
		// Verify that the key matches the role type
		if csr.PublicKeyAlgorithm != x509.ECDSA {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires keys of type %s",
				data.Role.KeyType)}
		}
		pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errutil.UserError{Err: "could not parse CSR's public key"}
		}

		// Verify that the bit size is at least the size specified in the role
		if pubKey.Params().BitSize < data.Role.KeyBits {
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"role requires a minimum of a %d-bit key, but CSR's key is %d bits",
				data.Role.KeyBits,
				pubKey.Params().BitSize)}
		}

	case "any":
		// We only care about running RSA < 2048 bit checks, so if not RSA
		// break out
		if csr.PublicKeyAlgorithm != x509.RSA {
			break
		}

		// Run RSA < 2048 bit checks
		pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errutil.UserError{Err: "could not parse CSR's public key"}
		}
		if pubKey.N.BitLen() < 2048 {
			return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
		}

	}

	creation, err := pki.GenerateConvertedCreationBundle(&b.pkiBackend.Backend, data, caSign, csr)
	if err != nil {
		return nil, err
	}
	if creation.Params == nil {
		return nil, errutil.InternalError{Err: "nil parameters received from parameter bundle generation"}
	}

	creation.Params.IsCA = isCA
	creation.Params.UseCSRValues = useCSRValues

	if isCA {
		creation.Params.PermittedDNSDomains = data.ApiData.Get("permitted_dns_domains").([]string)
	}

	parsedBundle, err := SignCertificate(b, creation)

	if err != nil {
		return nil, err
	}

	return parsedBundle, nil
}

func generateCert(ctx context.Context,
	b *HsmPkiBackend,
	input *pki.InputBundleA,
	caSign *certutil.CAInfoBundle,
	isCA bool) (*certutil.ParsedCertBundle, error) {

	if input.Role == nil {
		return nil, errutil.InternalError{Err: "no role found in data bundle"}
	}

	if input.Role.KeyType == "rsa" && input.Role.KeyBits < 2048 {
		return nil, errutil.UserError{Err: "RSA keys < 2048 bits are unsafe and not supported"}
	}

	data, err := pki.GenerateConvertedCreationBundle(&b.pkiBackend.Backend, input, caSign, nil)
	if err != nil {
		return nil, err
	}
	if data.Params == nil {
		return nil, errutil.InternalError{Err: "nil parameters received from parameter bundle generation"}
	}

	if isCA {
		data.Params.IsCA = isCA
		data.Params.PermittedDNSDomains = input.ApiData.Get("permitted_dns_domains").([]string)

		if data.SigningBundle == nil {
			// Generating a self-signed root certificate
			entries, err := pki.GetURLs(ctx, input.Req)
			if err != nil {
				return nil, errutil.InternalError{Err: fmt.Sprintf("unable to fetch URL information: %v", err)}
			}
			if entries == nil {
				entries = &certutil.URLEntries{
					IssuingCertificates:   []string{},
					CRLDistributionPoints: []string{},
					OCSPServers:           []string{},
				}
			}
			data.Params.URLs = entries

			if input.Role.MaxPathLength == nil {
				data.Params.MaxPathLength = -1
			} else {
				data.Params.MaxPathLength = *input.Role.MaxPathLength
			}
		}
	}

	parsedBundle, err := CreateCertificate(b, data)
	if err != nil {
		return nil, err
	}

	return parsedBundle, nil
}
