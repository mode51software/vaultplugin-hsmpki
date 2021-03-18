package hsmpki

import (
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/mode51software/vaultplugin-hsmpki/pkg/pki"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *HsmPkiBackend) getGenerationParams(
	data *framework.FieldData,
) (exported bool, format string, role *pki.RoleEntry, errorResp *logical.Response) {
	exportedStr := data.Get("exported").(string)
	switch exportedStr {
	case "exported":
		exported = true
	case "internal":
	default:
		errorResp = logical.ErrorResponse(
			`the "exported" path parameter must be "internal" or "exported"`)
		return
	}

	format = pki.GetFormat(data)
	if format == "" {
		errorResp = logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", "der_pkcs", or "pem_bundle"`)
		return
	}

	role = pki.GenRoleEntry()
	role.TTL = time.Duration(data.Get("ttl").(int)) * time.Second
	role.KeyType = data.Get("key_type").(string)
	role.KeyBits = data.Get("key_bits").(int)
	role.AllowLocalhost = true
	role.AllowAnyName = true
	role.AllowIPSANs = true
	role.EnforceHostnames = false
	role.AllowedURISANs = []string{"*"}
	role.AllowedOtherSANs = []string{"*"}
	role.AllowedSerialNumbers = []string{"*"}
	role.OU = data.Get("ou").([]string)
	role.Organization = data.Get("organization").([]string)
	role.Country = data.Get("country").([]string)
	role.Locality = data.Get("locality").([]string)
	role.Province = data.Get("province").([]string)
	role.StreetAddress = data.Get("street_address").([]string)
	role.PostalCode = data.Get("postal_code").([]string)

	if role.KeyType == "rsa" && role.KeyBits < 2048 {
		errorResp = logical.ErrorResponse("RSA keys < 2048 bits are unsafe and not supported")
		return
	}

	if err := certutil.ValidateKeyTypeLength(role.KeyType, role.KeyBits); err != nil {
		errorResp = logical.ErrorResponse(err.Error())
	}

	return
}

type roleEntry struct {
	LeaseMax                      string        `json:"lease_max"`
	Lease                         string        `json:"lease"`
	DeprecatedMaxTTL              string        `json:"max_ttl" mapstructure:"max_ttl"`
	DeprecatedTTL                 string        `json:"ttl" mapstructure:"ttl"`
	TTL                           time.Duration `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL                        time.Duration `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
	AllowLocalhost                bool          `json:"allow_localhost" mapstructure:"allow_localhost"`
	AllowedBaseDomain             string        `json:"allowed_base_domain" mapstructure:"allowed_base_domain"`
	AllowedDomainsOld             string        `json:"allowed_domains,omitempty"`
	AllowedDomains                []string      `json:"allowed_domains_list" mapstructure:"allowed_domains"`
	AllowedDomainsTemplate        bool          `json:"allowed_domains_template"`
	AllowBaseDomain               bool          `json:"allow_base_domain"`
	AllowBareDomains              bool          `json:"allow_bare_domains" mapstructure:"allow_bare_domains"`
	AllowTokenDisplayName         bool          `json:"allow_token_displayname" mapstructure:"allow_token_displayname"`
	AllowSubdomains               bool          `json:"allow_subdomains" mapstructure:"allow_subdomains"`
	AllowGlobDomains              bool          `json:"allow_glob_domains" mapstructure:"allow_glob_domains"`
	AllowAnyName                  bool          `json:"allow_any_name" mapstructure:"allow_any_name"`
	EnforceHostnames              bool          `json:"enforce_hostnames" mapstructure:"enforce_hostnames"`
	AllowIPSANs                   bool          `json:"allow_ip_sans" mapstructure:"allow_ip_sans"`
	ServerFlag                    bool          `json:"server_flag" mapstructure:"server_flag"`
	ClientFlag                    bool          `json:"client_flag" mapstructure:"client_flag"`
	CodeSigningFlag               bool          `json:"code_signing_flag" mapstructure:"code_signing_flag"`
	EmailProtectionFlag           bool          `json:"email_protection_flag" mapstructure:"email_protection_flag"`
	UseCSRCommonName              bool          `json:"use_csr_common_name" mapstructure:"use_csr_common_name"`
	UseCSRSANs                    bool          `json:"use_csr_sans" mapstructure:"use_csr_sans"`
	KeyType                       string        `json:"key_type" mapstructure:"key_type"`
	KeyBits                       int           `json:"key_bits" mapstructure:"key_bits"`
	MaxPathLength                 *int          `json:",omitempty" mapstructure:"max_path_length"`
	KeyUsageOld                   string        `json:"key_usage,omitempty"`
	KeyUsage                      []string      `json:"key_usage_list" mapstructure:"key_usage"`
	ExtKeyUsage                   []string      `json:"extended_key_usage_list" mapstructure:"extended_key_usage"`
	OUOld                         string        `json:"ou,omitempty"`
	OU                            []string      `json:"ou_list" mapstructure:"ou"`
	OrganizationOld               string        `json:"organization,omitempty"`
	Organization                  []string      `json:"organization_list" mapstructure:"organization"`
	Country                       []string      `json:"country" mapstructure:"country"`
	Locality                      []string      `json:"locality" mapstructure:"locality"`
	Province                      []string      `json:"province" mapstructure:"province"`
	StreetAddress                 []string      `json:"street_address" mapstructure:"street_address"`
	PostalCode                    []string      `json:"postal_code" mapstructure:"postal_code"`
	GenerateLease                 *bool         `json:"generate_lease,omitempty"`
	NoStore                       bool          `json:"no_store" mapstructure:"no_store"`
	RequireCN                     bool          `json:"require_cn" mapstructure:"require_cn"`
	AllowedOtherSANs              []string      `json:"allowed_other_sans" mapstructure:"allowed_other_sans"`
	AllowedSerialNumbers          []string      `json:"allowed_serial_numbers" mapstructure:"allowed_serial_numbers"`
	AllowedURISANs                []string      `json:"allowed_uri_sans" mapstructure:"allowed_uri_sans"`
	PolicyIdentifiers             []string      `json:"policy_identifiers" mapstructure:"policy_identifiers"`
	ExtKeyUsageOIDs               []string      `json:"ext_key_usage_oids" mapstructure:"ext_key_usage_oids"`
	BasicConstraintsValidForNonCA bool          `json:"basic_constraints_valid_for_non_ca" mapstructure:"basic_constraints_valid_for_non_ca"`
	NotBeforeDuration             time.Duration `json:"not_before_duration" mapstructure:"not_before_duration"`

	// Used internally for signing intermediates
	AllowExpirationPastCA bool
}
