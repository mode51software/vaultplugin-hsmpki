package hsmpki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/mode51software/pkcs11helper/pkg/pkcs11client"
	"time"
)

// Performs the heavy lifting of generating a certificate from a CSR.
// Returns a ParsedCertBundle sans private keys.
func SignCertificate(b *HsmPkiBackend, data *certutil.CreationBundle) (*certutil.ParsedCertBundle, error) {
	switch {
	case data == nil:
		return nil, errutil.UserError{Err: "nil data bundle given to signCertificate"}
	case data.Params == nil:
		return nil, errutil.UserError{Err: "nil parameters given to signCertificate"}
	case data.SigningBundle == nil:
		return nil, errutil.UserError{Err: "nil signing bundle given to signCertificate"}
	case data.CSR == nil:
		return nil, errutil.UserError{Err: "nil csr given to signCertificate"}
	}

	err := data.CSR.CheckSignature()
	if err != nil {
		return nil, errutil.UserError{Err: "request signature invalid"}
	}

	result := &certutil.ParsedCertBundle{}

	serialNumber, err := certutil.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	marshaledKey, err := x509.MarshalPKIXPublicKey(data.CSR.PublicKey)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error marshalling public key: %s", err)}
	}
	subjKeyID := sha1.Sum(marshaledKey)

	caCert := data.SigningBundle.Certificate

	certTemplate := &x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        data.Params.Subject,
		NotBefore:      time.Now().Add(-30 * time.Second),
		NotAfter:       data.Params.NotAfter,
		SubjectKeyId:   subjKeyID[:],
		AuthorityKeyId: caCert.SubjectKeyId,
	}
	if data.Params.NotBeforeDuration > 0 {
		certTemplate.NotBefore = time.Now().Add(-1 * data.Params.NotBeforeDuration)
	}

	certTemplate.SignatureAlgorithm = selectHashAlgo(data.SigningBundle.Certificate.PublicKeyAlgorithm, b.cachedCAConfig.hashAlgo)
	if certTemplate.SignatureAlgorithm == 0 {
		return nil, errutil.InternalError{Err: errwrap.Wrapf("Unknown SignatureAlgorithm", nil).Error()}
	}

	if data.Params.UseCSRValues {
		certTemplate.Subject = data.CSR.Subject
		certTemplate.Subject.ExtraNames = certTemplate.Subject.Names

		certTemplate.DNSNames = data.CSR.DNSNames
		certTemplate.EmailAddresses = data.CSR.EmailAddresses
		certTemplate.IPAddresses = data.CSR.IPAddresses
		certTemplate.URIs = data.CSR.URIs

		for _, name := range data.CSR.Extensions {
			if !name.Id.Equal(oidExtensionBasicConstraints) {
				certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, name)
			}
		}

	} else {
		certTemplate.DNSNames = data.Params.DNSNames
		certTemplate.EmailAddresses = data.Params.EmailAddresses
		certTemplate.IPAddresses = data.Params.IPAddresses
		certTemplate.URIs = data.Params.URIs
	}

	if err := certutil.HandleOtherSANs(certTemplate, data.Params.OtherSANs); err != nil {
		return nil, errutil.InternalError{Err: errwrap.Wrapf("error marshaling other SANs: {{err}}", err).Error()}
	}

	certutil.AddPolicyIdentifiers(data, certTemplate)

	certutil.AddKeyUsages(data, certTemplate)

	certutil.AddExtKeyUsageOids(data, certTemplate)

	var certBytes []byte

	certTemplate.IssuingCertificateURL = data.Params.URLs.IssuingCertificates
	certTemplate.CRLDistributionPoints = data.Params.URLs.CRLDistributionPoints
	certTemplate.OCSPServer = data.SigningBundle.URLs.OCSPServers

	if data.Params.IsCA {
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = true

		if data.SigningBundle.Certificate.MaxPathLen == 0 &&
			data.SigningBundle.Certificate.MaxPathLenZero {
			return nil, errutil.UserError{Err: "signing certificate has a max path length of zero, and cannot issue further CA certificates"}
		}

		certTemplate.MaxPathLen = data.Params.MaxPathLength
		if certTemplate.MaxPathLen == 0 {
			certTemplate.MaxPathLenZero = true
		}
	} else if data.Params.BasicConstraintsValidForNonCA {
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = false
	}

	if len(data.Params.PermittedDNSDomains) > 0 {
		certTemplate.PermittedDNSDomains = data.Params.PermittedDNSDomains
		certTemplate.PermittedDNSDomainsCritical = true
	}

	// serial number is managed by vault
	// certTemplate is managed by vault so SignatureAlgorithm not used here
	var caSigner pkcs11client.HsmSigner
	caSigner.KeyConfig.Label = b.cachedCAConfig.caKeyAlias //"ECTestCAInterKey0016"
	caSigner.Pkcs11Client = &b.pkcs11client
	caSigner.PublicKey = data.SigningBundle.Certificate.PublicKey

	//pubKey, err := b.pkcs11client.ReadECPublicKey(&caSigner.KeyConfig)
	//caSigner.PublicKey = pubKey

	b.pkcs11client.Pkcs11Mutex.Lock()

	certBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, caCert, data.CSR.PublicKey, caSigner)

	// whilst the Pkcs11Client is locked, the last error and code can be used

	if b.pkcs11client.LastErrCode == pkcs11client.PKCS11ERR_READTIMEOUT {
		b.pkiBackend.Backend.Logger().Info("pkcs11helper: Timeout processing PKCS#11 function")
		b.checkPkcs11ConnectionFailed()
	} else if b.pkcs11client.LastErrCode == pkcs11client.PKCS11ERR_GENERICERROR {
		b.pkiBackend.Backend.Logger().Info("pkcs11helper: generic error")
		// TODO: defend against deliberate errors which cause a reconnection attempt
		b.checkPkcs11ConnectionFailed()
	} else if b.pkcs11client.LastErrCode == 0 {
		b.pkiBackend.Backend.Logger().Info("pkcs11helper: no error")
	}

	b.pkcs11client.Pkcs11Mutex.Unlock() // unlock asap rather than have deferred

	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to create certificate: %s", err)}
	}

	result.CertificateBytes = certBytes
	result.Certificate, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to parse created certificate: %s", err)}
	}

	result.CAChain = data.SigningBundle.GetCAChain()

	return result, nil
}

// Performs the heavy lifting of creating a certificate. Returns
// a fully-filled-in ParsedCertBundle.
func CreateCertificate(b *HsmPkiBackend, data *certutil.CreationBundle) (*certutil.ParsedCertBundle, error) {
	var err error
	result := &certutil.ParsedCertBundle{}

	serialNumber, err := certutil.GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	if err := certutil.GeneratePrivateKey(data.Params.KeyType,
		data.Params.KeyBits,
		result); err != nil {
		return nil, err
	}

	subjKeyID, err := certutil.GetSubjKeyID(result.PrivateKey)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error getting subject key ID: %s", err)}
	}

	certTemplate := &x509.Certificate{
		SerialNumber:   serialNumber,
		NotBefore:      time.Now().Add(-30 * time.Second),
		NotAfter:       data.Params.NotAfter,
		IsCA:           false,
		SubjectKeyId:   subjKeyID,
		Subject:        data.Params.Subject,
		DNSNames:       data.Params.DNSNames,
		EmailAddresses: data.Params.EmailAddresses,
		IPAddresses:    data.Params.IPAddresses,
		URIs:           data.Params.URIs,
	}
	if data.Params.NotBeforeDuration > 0 {
		certTemplate.NotBefore = time.Now().Add(-1 * data.Params.NotBeforeDuration)
	}

	if err := certutil.HandleOtherSANs(certTemplate, data.Params.OtherSANs); err != nil {
		return nil, errutil.InternalError{Err: errwrap.Wrapf("error marshaling other SANs: {{err}}", err).Error()}
	}

	// Add this before calling addKeyUsages
	if data.SigningBundle == nil {
		certTemplate.IsCA = true
	} else if data.Params.BasicConstraintsValidForNonCA {
		certTemplate.BasicConstraintsValid = true
		certTemplate.IsCA = false
	}

	// This will only be filled in from the generation paths
	if len(data.Params.PermittedDNSDomains) > 0 {
		certTemplate.PermittedDNSDomains = data.Params.PermittedDNSDomains
		certTemplate.PermittedDNSDomainsCritical = true
	}

	certutil.AddPolicyIdentifiers(data, certTemplate)

	certutil.AddKeyUsages(data, certTemplate)

	certutil.AddExtKeyUsageOids(data, certTemplate)

	certTemplate.IssuingCertificateURL = data.Params.URLs.IssuingCertificates
	certTemplate.CRLDistributionPoints = data.Params.URLs.CRLDistributionPoints
	certTemplate.OCSPServer = data.Params.URLs.OCSPServers

	var certBytes []byte
	if data.SigningBundle != nil {

		certTemplate.SignatureAlgorithm = selectHashAlgo(data.SigningBundle.Certificate.PublicKeyAlgorithm, b.cachedCAConfig.hashAlgo)
		if certTemplate.SignatureAlgorithm == 0 {
			return nil, errutil.InternalError{Err: errwrap.Wrapf("Unknown SignatureAlgorithm", nil).Error()}
		}

		caCert := data.SigningBundle.Certificate
		certTemplate.AuthorityKeyId = caCert.SubjectKeyId

		var caSigner pkcs11client.HsmSigner
		caSigner.KeyConfig.Label = b.cachedCAConfig.caKeyAlias
		caSigner.Pkcs11Client = &b.pkcs11client
		caSigner.PublicKey = data.SigningBundle.Certificate.PublicKey

		certBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, caCert, result.PrivateKey.Public(), caSigner) //data.SigningBundle.PrivateKey)
	} else {
		return nil, errutil.InternalError{Err: errwrap.Wrapf("Self-signed roots are unsupported", nil).Error()}
	}

	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to create certificate: %s", err)}
	}

	result.CertificateBytes = certBytes
	result.Certificate, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("unable to parse created certificate: %s", err)}
	}

	if data.SigningBundle != nil {
		if len(data.SigningBundle.Certificate.AuthorityKeyId) > 0 &&
			!bytes.Equal(data.SigningBundle.Certificate.AuthorityKeyId, data.SigningBundle.Certificate.SubjectKeyId) {

			result.CAChain = []*certutil.CertBlock{
				&certutil.CertBlock{
					Certificate: data.SigningBundle.Certificate,
					Bytes:       data.SigningBundle.CertificateBytes,
				},
			}
			result.CAChain = append(result.CAChain, data.SigningBundle.CAChain...)
		}
	}

	return result, nil
}

func selectHashAlgo(pubKeyAlgo x509.PublicKeyAlgorithm, cachedHashAlgo crypto.Hash) x509.SignatureAlgorithm {

	switch pubKeyAlgo {

	case x509.RSA:
		// we don't need to specify whether to use RSASSA-PKCS-v1.5 or RSASSA-PSS here
		// because the pkcs11helper.HsmSigner auto detects this from the CA's public key
		switch cachedHashAlgo {
		case crypto.SHA384:
			return x509.SHA384WithRSA
		case crypto.SHA512:
			return x509.SHA512WithRSA
		case crypto.SHA256:
			fallthrough
		default:
			return x509.SHA256WithRSA
		}

	case x509.ECDSA:
		switch cachedHashAlgo {
		case crypto.SHA384:
			return x509.ECDSAWithSHA384
		case crypto.SHA512:
			return x509.ECDSAWithSHA512
		case crypto.SHA256:
			fallthrough
		default:
			return x509.ECDSAWithSHA256
		}

	default:
		return 0

	}
}
