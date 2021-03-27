## v0.3.4
### 27/03/2021

* Sign Self Issued

## v0.3.3
### 18/03/2021

* Bugfix for key label in relation to persistent storage
* pathSignVerbatim

## v0.3.2.beta.1
### 17/Mar/2021

* Improved connection checks
* RSA keys for Generate Root and Generate Intermediate (initially hard coded to EC)  
* Remove hardcoded key types except for CSR gen as part of Generate Intermediate
* Detect if in metamode on startup

## v0.3.1.beta.1
### 14/Mar/2021

* Added Generate Root, Generate Intermediate and Sign Intermediate paths

## v0.3.0
### 01/Mar/2021

* Initial release with support for HSM signing using an externally generated CA cert imported using Vault's Set Signed Intermediate command
