package hsmpki

const (
	PATH_CA                    = "ca"
	PATH_CAKEYLABEL            = "cert/ca_keylabel"
	PATH_CERTS                 = "certs/"
	PATH_ROLE                  = "role/"
	PATH_SETSIGNEDINTERMEDIATE = "intermediate/set-signed"
	PATH_SETCRLCONFIG          = "config/crl"
	PATH_FETCHCRL              = "crl"
	PATH_REVOKE                = "revoke"
	PATH_TIDY                  = "tidy"
	PATH_ROTATECRL             = "crl/rotate"
	PATH_GENERATEROOT          = "root/generate/"
	PATH_GENERATEINTERMEDIATE  = "intermediate/generate/"
	PATH_SIGNINTERMEDIATE      = "root/sign-intermediate"
	PATH_ISSUE                 = "issue/"

	PATH_HASHALGO = "hash_algo"

	FIELD_ROLE                = "role"
	FIELD_KEYALIAS            = "key_label"
	FIELD_HASHALGO            = "hash_algo"
	FIELD_COMMON_NAME         = "common_name"
	FIELD_TYPE                = "type"
	FIELD_EXPORTED            = "exported"
	FIELD_TTL                 = "ttl"
	FIELD_KEY_TYPE            = "key_type"
	FIELD_KEY_BITS            = "key_bits"
	FIELD_PERMITTED_DNS_NAMES = "permitted_dns_names"
	FIELD_ORGANIZATION        = "organization"
	FIELD_OU                  = "ou"
	FIELD_COUNTRY             = "country"
	FIELD_LOCALITY            = "locality"
	FIELD_PROVINCE            = "province"
	FIELD_STREET_ADDRESS      = "street_address"
	FIELD_POSTAL_CODE         = "postal_code"
	FIELD_CSR                 = "csr"
	FIELD_CERTIFICATE         = "certificate"

	CONFIG_PARAM = "config"

	CONFIG_PLUGIN_NAME = "plugin_name"

	PLUGIN_HELP = "The hsmpki backend is a PKI plugin that uses an HSM for CA signing."

	DEFAULT_CRL_LIFETIME = 72

	//ROOTCA_BUNDLE  = "config/rootca_bundle"
	//INTERCA_BUNDLE = "config/ca_bundle"
	CA_BUNDLE = "config/ca_bundle"
	// relative to test working directory in pkg/hsmpki
	//TEST_CONFIG_HSM = "../../conf/config-softhsm.hcl"
	TEST_CONFIG_HSM = "../../conf/config-safenet.hcl"

	TEST_EXPORTED        = "internal"
	TEST_ROLENAME        = "localhost"
	TEST_ALLOWED_DOMAINS = "localhost"
	TEST_MAX_TTL         = "72h"
	TEST_TTL             = "1h"
	TEST_COMMON_NAME     = "localhost"
	TEST_ROLE_NAME       = "localhost"
	//TEST_SIGNEDCACERTFILE 	= "../../data/softhsm-inter-0002.ca.cert.pem"
	TEST_SIGNEDCACERTFILE      = "../../data/safenet-inter-0016.ca.cert.pem"
	TEST_ROOTCACERTFILE        = "../../data/testrootca.cert.pem"
	TEST_INTERCSRFILE          = "../../data/testintermediate.csr.pem"
	TEST_INTERCERTFILE         = "../../data/testintermediate.cert.pem"
	TEST_CAROOTCOMMONNAME      = "safenet.ec17.rootca.mode51.software"
	TEST_CAINTERCOMMONNAME     = "safenet.ec17.interca.mode51.software"
	TEST_CAKEYTYPE             = "ec"
	TEST_CAKEYBITS             = "521"
	TEST_CAPERMITTEDDNSDOMAINS = "localhost"
	TEST_CAORGANIZATION        = "mode51 Software Ltd"
	TEST_CAOU                  = "Security"
	TEST_CACOUNTRY             = "GB"
	TEST_CAPROVINCE            = "Cambridgeshire"
	TEST_CALOCALITY            = "Cambridge"
	TEST_CASTREETADDRESS       = "1 The Street"
	TEST_CAPOSTALCODE          = "CB1 1AA"
	TEST_CATTL                 = 8 * 60
)

var oidExtensionBasicConstraints = []int{2, 5, 29, 19}
