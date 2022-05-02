# Vault HSM PKI Plugin Installation

These instructions enable the persistent installation of the HSM PKI plugin. The README contains instructions only for running in memory with a development instance of Vault.

## Install
- Create the directory where Vault will look for plugins:

```
/etc/vault/vault_plugins
```

- Locate the Vault server configuration file:

```
vi /etc/vault/config.json
```
- Specify the plugin directory in the Vault server configuration file:

```
plugin_directory = "/etc/vault/vault_plugins"
```

- Deploy the latest HSM PKI release:

```
wget https://github.com/mode51software/vaultplugin-hsmpki/releases/download/v0.3.4/vaultplugin-hsmpki-v0_3_4.bz2
bunzip2 vaultplugin-hsmpki-v0_3_4.bz2
sudo mv vaultplugin-hsmpki-v0_3_4 /etc/vault/vault_plugins/vaultplugin-hsmpki
chmod 755 /etc/vault/vault_plugins/vaultplugin-hsmpki
```

- For SafeNet DPoD first run setenv:

```
cd /opt/safenet/dpod/current
. ./setenv
cd <this git repo download directory>
```

- Start Vault using the server command and unseal it:

```
vault server -config /etc/vault/config.json

export VAULT_ADDR='http://127.0.0.1:8200'

vault operator unseal
```

- Login using the root token:

```
vault login
```

- Get the SHA-256 checksum of the vaultplugin-hsmpki plugin binary:

```
SHA256=$(sha256sum /etc/vault/vault_plugins/vaultplugin-hsmpki-v0_3_4| cut -d' ' -f1)
```

- Register the vaultplugin-hsmpki plugin in the Vault system catalog:

```
vault write sys/plugins/catalog/secret/vaultplugin-hsmpki sha_256="${SHA256}" command="vaultplugin-hsmpki"

Success! Data written to: sys/plugins/catalog/secret/vaultplugin-hsmpki
```

- Enable the HSM PKI secrets engine paths.

Note that the HSM config file needs to be relative to the calling path:

```
vault secrets enable -path=hsmpki_root -options="config=conf/config-safenet.hcl" vaultplugin-hsmpki

Success! Enabled the vaultplugin-hsmpki secrets engine at: hsmpki_root/
```

```
vault secrets enable -path=hsmpki_inter -options="config=conf/config-safenet.hcl" vaultplugin-hsmpki

Success! Enabled the vaultplugin-hsmpki secrets engine at: hsmpki_inter/
```

Now refer to the [README.md](README.md) and create certificates.


## Environment

### SafeNet DPoD

The setenv script sets the following environment var. Please use the path to the root of your SafeNet DPoD files:

```
declare -x ChrystokiConfigurationPath="/opt/safenet/dpod/current"
```

This can also be set in the service section of the systemd configuration file:

```
Environment="ChrystokiConfigurationPath=/opt/safenet/dpod/current"
```

