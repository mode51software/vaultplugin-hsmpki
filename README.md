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

#### Setup Without CA Generation

These instructions apply if the Intermediate CA has been created and signed by a Root CA externally to Vault.

##### Enable the HSM PKI plugin:

`vault secrets enable -path=hsmpki_inter -options="config=conf/config-softhsm.hcl" vaultplugin-hsmpki`

#### Setup With CA Generation

These instructions apply if the Root and Intermediate CAs need to be created and signed by Vault.

##### Enable the HSM PKI plugin paths:

* Different configuration files can be passed to each instance of the plugin. 
* These may contain alternative HSM slot and PIN settings.
* If no key label is specified then one will be automatically generated and stored within Vault.
* The automatically generated key label is provided in the response to the Generate Root and Generate Intermediate commands.

Root CA path:
`vault secrets enable -path=hsmpki_root -options="config=conf/config-safenet.hcl" vaultplugin-hsmpki`

Intermediate CA path:
`vault secrets enable -path=hsmpki_inter -options="config=conf/config-safenet.hcl" vaultplugin-hsmpki`

### Run Create CA certs and Issue

In this sequence of steps Vault:

* generates a Root CA cert using the hsmpki_root path
* generate an Intermediate CA and CSR using the hsmpki_inter path
* signs the Intermediate CA's CSR producing the cert using the hsmpki_root path
* sets the signed Intermediate CA using the hsmpki_inter path
* creates a role  
* issues a new private key and a new cert signed by the Intermediate CA using the hsmpki_path    

#### Generate Root CA

Notice that key_label is returned alongside serial_number. Also note that the certificate is the same as the issuing certificate.

A key label for the HSM will be generated automatically if a key_label isn't specified in the conf file.

The format of the automatically generated key_label is eg. ROOTCA20210314232939

`vault write hsmpki_root/root/generate/internal common_name=safenet.ec.ca.mode51.software key_type=ec key_bits=521 permitted_dns_domains=localhost organization="mode51 Software Ltd" ou="Software" country="GB" locality="Cambridge" province="Cambridgeshire" street_address="1 A Street" postal_code="CB1"`

Save the signed Intermediate CA to a file eg. data/root.cert.pem

This CA cert can be imported into a browser for testing.

#### Generate Intermediate CA and CSR

The format of the automatically generated key_label is eg. INCA20210314233609

`vault write hsmpki_inter/intermediate/generate/internal common_name=safenet.ec.interca.mode51.software key_type=ec key_bits=384 permitted_dns_domains=localhost organization="mode51 Software Ltd" ou="Software" country="GB" locality="Cambridge" province="Cambridgeshire" street_address="1 A Street" postal_code="CB1"`

Save the CSR to a file, eg. data/intermediate.csr.pem

Use openssl to check the CSR:

`openssl req -in ./data/intermediate.csr.pem -text`

#### Sign the Intermediate CA

`vault write hsmpki_root/root/sign-intermediate csr=@data/intermediate.csr.pem common_name=safenet.ec.interca.mode51.software key_type=ec key_bits=384 permitted_dns_domains=localhost organization="mode51 Software Ltd" ou="Software" country="GB" locality="Cambridge" province="Cambridgeshire" street_address="1 A Street" postal_code="CB1"`

Save the signed Intermediate CA to a file eg. data/intermediate.cert.pem

This CA cert can be imported into a browser for testing.

#### Set the Signed Intermediate CA

If the key label has been automatically generated as part of the Generate Intermediate command then it doesn't need to be specified here or in the conf file:

`vault write hsmpki_inter/intermediate/set-signed certificate=@data/intermediate.cert.pem hash_algo="SHA-512"`

#### Create a Role

Create a role for the allowed domain, which configures the certificate signing template, in this case localhost:

`vault write hsmpki_inter/roles/localhost allowed_domains=localhost allow_subdomains=true ttl=24h max_ttl=72h key_type="ec" key_bits="384"`

#### Issue a New Signed Cert

Ask Vault to create a new key pair, generate a CSR and sign it using the HSM, returning both the private key, the CA and the signed certificate:

`vault write hsmpki_inter/issue/localhost common_name=localhost`


### Run Signing Using an Externally Generated and Signed CA

#### Set the Signed Intermediate CA

Set the signed Intermediate certificate and use the HSM PKI extensions supporting the configuration of the HSM key alias and the preferred SHA algorithm.

The key label can also be configured in the conf file passed in to the secrets enable command:

`vault write hsmpki_inter/intermediate/set-signed certificate=@data/safenet-inter-0016.ca.cert.pem key_label="ECTestCAInterKey0016" hash_algo="SHA-512"`

#### Create a Role

Create a role for the allowed domain, which configures the certificate signing template, in this case localhost:

`vault write hsmpki_inter/roles/localhost allowed_domains=localhost allow_subdomains=true ttl=24h max_ttl=72h key_type="ec" key_bits="384"`

#### Sign a CSR

Now that Vault is ready for signing, sign a standalone CSR file using the HSM returning the CA and the signed certificate:

`vault write hsmpki_inter/sign/localhost csr=@data/localhost512.csr.pem`

#### Issue a New Cert

Ask Vault to create a new key pair, generate a CSR and sign it using the HSM, returning both the private key, the CA and the signed certificate:

`vault write hsmpki_inter/issue/localhost common_name=localhost`

#### Revoke a Certificate

`vault write hsmpki_inter/revoke serial_number="<your serial number>"`

#### View Revocation Time of Certificate

`vault read hsmpki_inter/cert/<your serial number>`

#### View CRL

`curl --header "X-Vault-Token: root"  http://127.0.0.1:8200/v1/hsmpki_inter/crl/pem > data/crl.txt`

`openssl crl -in ./data/crl.txt -text`

### Verify Certs

Install nginx and setup the TLS certificate and private key for the test site, 
referred to below as localhost.crt and localhost.key.

These are the private key and the certificate generated by Vault's issue command.

Separately import the Root CA and Intermediate CA into a web browser.

Visit https://localhost:444/ and confirm that the TLS certificate is accepted.

```
server {

listen              444 ssl http2 default_server;

server_name         localhost;

ssl_certificate     /etc/nginx/certs/localhost.crt;

ssl_certificate_key /etc/nginx/certs/localhost.key;

ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;

ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
      root   /usr/share/nginx/html;
      index  index.html index.htm;
    }
```

### Testing

View the [TESTING](TESTING.md) README

### Troubleshooting

#### SafeNet DPoD [Troubleshooting](https://thalesdocs.com/dpod/services/hsmod_services/hsmod_troubleshooting/index.html)

##### HSM error code 0x80001604

This may indicate that the SafeNet DPoD partition is full

## License

HSM PKI for Vault was sponsored by [BT UK](https://www.globalservices.bt.com/en/aboutus/our-services/security), developed by [mode51 Software](https://mode51.software), and contributed to the [HashiCorp community](https://www.vaultproject.io/docs/plugin-portal) under the Mozilla Public License v2.

By [Chris Newman](https://mode51.software)
