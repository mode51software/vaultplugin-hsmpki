# Vault HSM PKI Plugin

The Vault HSM PKI plugin overlays the modifications to the builtin PKI plugin that enable support for certificate signing using a Hardware Security Module via [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

## Software Design

### Reuse of builtin PKI

The [builtin PKI](https://github.com/hashicorp/vault/tree/v1.6.3/builtin/logical/pki) has a [specified API](https://www.vaultproject.io/api-docs/secret/pki) in terms of usage which new plugins can conform to, but the code is not expressed as a reusable module. 

As this HSM plugin seeks to retain the majority of existing functionality without modification, eg. roles, the builtin PKI code is included in the [pkg/pki](./pkg/pki) directory with the addition of the pki_api.go file that makes select functions externally accessible. The rest of the included PKI code is included verbatim in the pkg/pki directory.

The HSM PKI plugin can therefore selectively override some of the PKI paths whilst using some unchanged paths.

## Usage

### Dependencies

[Go](https://golang.org/doc/install)

[Vault](https://www.vaultproject.io/downloads)

### Setup HSMs

The [pkcs11helper module](https://github.com/mode51software/pkcs11helper) provides [detailed setup instructions](https://github.com/mode51software/pkcs11helper/blob/master/SETUP.md) for SoftHSM, Thales's SafeNet and Entrust's nShield.

### Build

Note that the following env var may be needed:

export GOSUMDB=off

The following command will build the plugin binary and start the Vault server as an in memory dev instance:

```
make
```

Visit [INSTALL.md](INSTALL.md) for the plugin installation and registration details.

### Login 
Now open a new terminal window and login to Vault. This is an example for a dev instance:

`export VAULT_ADDR='http://127.0.0.1:8200'`

`vault login root`

### Setup

Enable the HSM PKI plugin:

`vault secrets enable -path=hsmpki -options="config=conf/config-softhsm.hcl" vaultplugin-hsmpki`

### Run

#### Create a Role

Create a role for the allowed domain, which configures the certificate signing template, in this case localhost:

`vault write hsmpki/roles/localhost allowed_domains=localhost allow_subdomains=true ttl=24h max_ttl=72h key_type="ec" key_bits="384"`

#### Set the Signed Intermediate CA

Set the signed Intermediate certificate and use the HSM PKI extensions supporting the configuration of the HSM key alias and the preferred SHA algorithm :

`vault write hsmpki/intermediate/set-signed certificate=@data/safenet-inter-0016.ca.cert.pem key_alias="ECTestCAInterKey0016" hash_algo="SHA-512"`

#### Sign a CSR
Now that Vault is ready for signing, sign a standalone CSR file using the HSM returning the CA and the signed certificate:

`vault write hsmpki/sign/localhost csr=@data/localhost512.csr.pem`

#### Generate a Key, CSR and Sign

Ask Vault to create a new key pair, generate a CSR and sign it using the HSM, returning both the private key, the CA and the signed certificate:

`vault write hsmpki/issue/localhost common_name=localhost`

#### Revoke a Certificate

`vault write hsmpki/revoke serial_number="<your serial number>"`

#### View Revocation Time of Certificate

`vault read hsmpki/cert/<your serial number>`

#### View CRL

`curl --header "X-Vault-Token: root"  http://127.0.0.1:8200/v1/hsmpki/crl/pem > data/crl.txt`

`openssl crl -in ./data/crl.txt -text`

### Testing

View the [TESTING](TESTING.md) README

## License

HSM PKI for Vault was sponsored by [BT UK](https://www.globalservices.bt.com/en/aboutus/our-services/security), developed by [mode51 Software](https://mode51.software), and contributed to the [HashiCorp community](https://www.vaultproject.io/docs/plugin-portal) under the Mozilla Public License v2.

By [Chris Newman](https://mode51.software)
