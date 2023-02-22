#! /bin/bash

## MACSec Configuration
export MKA_CKA=aaaabbbbccccdddd1234567812345678
export MKA_CKN=0000111122223333444455556666777788889999001122334455667788990123

nmcli connection del macsec-connection

nmcli connection add type macsec \
con-name macsec-connection \
ifname macsec0 \
connection.autoconnect no \
macsec.parent enp0s3 \
macsec.mode psk \
macsec.mka-cak $MKA_CKA \
macsec.mka-cak-flags 0 \
macsec.mka-ckn $MKA_CKN \
ipv4.method manual \
ipv4.addresses 10.23.0.3/24

nmcli connection up macsec-connection

## IP routing
ip r a default via 10.23.0.1