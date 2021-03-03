package hsmpki

const (
	PATH_CA                    = "ca"
	PATH_CAKEYALIAS            = "cert/ca_keyalias"
	PATH_CERTS                 = "certs/"
	PATH_ROLE                  = "role/"
	PATH_SETSIGNEDINTERMEDIATE = "intermediate/set-signed"
	PATH_SETCRLCONFIG          = "config/crl"
	PATH_FETCHCRL              = "crl"
	PATH_REVOKE                = "revoke"
	PATH_TIDY                  = "tidy"
	PATH_ROTATECRL             = "crl/rotate"

	PATH_HASHALGO = "hash_algo"

	FIELD_KEYALIAS = "key_alias"
	FIELD_HASHALGO = "hash_algo"

	CONFIG_PARAM = "config"

	CONFIG_PLUGIN_NAME = "plugin_name"

	PLUGIN_HELP = "The hsmpki backend is a PKI plugin that uses an HSM for CA signing."

	DEFAULT_CRL_LIFETIME = 72

	// relative to test working directory in pkg/hsmpki
	//TEST_CONFIG_HSM = "../../conf/config-softhsm.hcl"
	TEST_CONFIG_HSM = "../../conf/config-safenet.hcl"

	TEST_ROLENAME        = "localhost"
	TEST_ALLOWED_DOMAINS = "localhost"
	TEST_MAX_TTL         = "72h"
	TEST_TTL             = "1h"

	//TEST_SIGNEDCACERTFILE = "../../data/softhsm-inter-0002.ca.cert.pem"
	TEST_SIGNEDCACERTFILE = "../../data/safenet-inter-0016.ca.cert.pem"
)

var oidExtensionBasicConstraints = []int{2, 5, 29, 19}
