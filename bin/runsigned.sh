export VAULT_ADDR='http://127.0.0.1:8200'

vault login root

vault secrets enable -path=hsmpki -options="config=conf/config-softhsm.hcl" vaultplugin-hsmpki

vault write hsmpki/roles/localhost allowed_domains=localhost allow_subdomains=true max_ttl=72h

vault write hsmpki/intermediate/set-signed certificate=@data/softhsm-inter-0002.ca.cert.pem key_alias="RSATestCAInterKey0002" hash_algo="SHA-384"

vault write hsmpki/config/crl expiry=48h

#vault write hsmpki/sign/localhost csr=@data/localhost512.csr.pem

#vault write hsmpki/issue/localhost common_name=localhost
