
lib = "/opt/apps/nfast/20201219/bin/libcknfast.so"
# list slots using pkcs11-tool -L --module /opt/nfast/toolkits/pkcs11/libcknfast.so and use the decimal slot ID
slot_id = 761406614
pin = "1234"
# be aware that the key_label can be overridden by dynamically providing it during Set Signed Intermediate
#key_label = "ECTestCAInterKey0016"
#key_label = "ECTestCARootKey0017"
connect_timeout_s = 10
read_timeout_s = 5
