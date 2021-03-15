module github.com/mode51software/vaultplugin-hsmpki

go 1.13

replace (
	github.com/mode51software/pkcs11helper => ../../../go/pkcs11helper/pkcs11helper
)

require (
	github.com/asaskevich/govalidator v0.0.0-20180720115003-f9ffefc3facf
	github.com/fatih/structs v1.1.0
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/hcl v1.0.1-vault
	github.com/hashicorp/vault v1.6.2
	github.com/hashicorp/vault/api v1.0.5-0.20201001211907-38d91b749c77
	github.com/hashicorp/vault/sdk v0.1.14-0.20210127182440-8477cfe632c0
	github.com/miekg/pkcs11 v1.0.3
	github.com/mode51software/pkcs11helper v0.3.1
	github.com/ryanuber/go-glob v1.0.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
)
