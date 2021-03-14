package hsmpki

import (
	"errors"
	"fmt"
	"github.com/mode51software/pkcs11helper/pkg/pkcs11client"
	"strconv"
	"time"
)

type HsmPkiConfig struct {

	// the PKCS#11 client library file
	Lib string

	// the slot ID on the HSM
	SlotId string `hcl:"slot_id"`

	// the slot's PIN
	Pin string

	// the HSM key label
	KeyLabel string `hcl:"key_label"`

	// connection timeout seconds
	ConnectTimeoutS string `hcl:"connect_timeout_s"`

	// function timeout seconds
	ReadTimeoutS string `hcl:"read_timeout_s"`
}

type HsmConfigCompat struct {
	// the HSM's client PKCS#11 library
	Lib string

	// the HSM slot ID
	SlotId uint `json:"slot_id"`

	// the slot pin
	Pin string

	// a key label
	KeyLabel string `json:"key_label"`

	// connection timeout seconds
	ConnectTimeoutS uint `json:"connect_timeout_s"`

	// function timeout seconds
	ReadTimeoutS uint `json:"read_timeout_s"`
}

// only check the presence of the client lib
// the slot could b 0, the pin could be blank and the key label could be set dynamically
func (h *HsmPkiConfig) ValidateConfig() error {
	if len(h.Lib) == 0 {
		return errors.New("Please specify the path of the PKCS#11 client library")
	}
	return nil
}

func (h *HsmPkiConfig) ConvertHsmConfig(hsmConfig *HsmConfigCompat) {

	hsmConfig.Lib = h.Lib
	slotId, _ := strconv.ParseUint(h.SlotId, 10, 32)
	hsmConfig.SlotId = uint(slotId)
	hsmConfig.Pin = h.Pin
	connectTimeoutS, _ := strconv.ParseUint(h.ConnectTimeoutS, 10, 32)
	hsmConfig.ConnectTimeoutS = uint(connectTimeoutS)
	readTimeoutS, _ := strconv.ParseUint(h.ReadTimeoutS, 10, 32)
	hsmConfig.ReadTimeoutS = uint(readTimeoutS)
}

func (h *HsmPkiConfig) ConvertToHsmConfig() (hsmConfig *pkcs11client.HsmConfig) {
	hsmConfig = &(pkcs11client.HsmConfig{})
	hsmConfig.Lib = h.Lib
	slotId, _ := strconv.ParseUint(h.SlotId, 10, 32)
	hsmConfig.SlotId = uint(slotId)
	hsmConfig.Pin = h.Pin
	hsmConfig.KeyLabel = h.KeyLabel
	connectTimeoutS, _ := strconv.ParseUint(h.ConnectTimeoutS, 10, 32)
	hsmConfig.ConnectTimeoutS = uint(connectTimeoutS)
	readTimeoutS, _ := strconv.ParseUint(h.ReadTimeoutS, 10, 32)
	hsmConfig.ReadTimeoutS = uint(readTimeoutS)
	return
}

func GenDateTimeKeyLabel() (keyLabel string) {
	t := time.Now()
	keyLabel = fmt.Sprintf("%d%02d%02d%02d%02d%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second())
	return
}
