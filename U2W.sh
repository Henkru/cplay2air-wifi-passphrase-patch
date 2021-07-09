#!/bin/sh

# Note: This has to be exactly 8 character long!
PASSPHRASE=changeme

# Ensure we have both files
[ -f "/mnt/UPAN/inject.o" ] || [ -f "/mnt/UPAN/proxy.sh" ] || exit 1

echo "[+] Install the shared library"
cp /mnt/UPAN/inject.o /usr/lib

if [ -f "/usr/sbin/ARMiPhoneIAP2_org" ]; then
    echo "[+] The original binary already exists"
else
    echo "[+] Rename the original biary to ARMiPhoneIAP2_org"
    mv "/usr/sbin/ARMiPhoneIAP2" "/usr/sbin/ARMiPhoneIAP2_org"
fi

echo "[+] Install the proxy script"
cp /mnt/UPAN/proxy.sh /usr/sbin/ARMiPhoneIAP2

echo "[+] Change file permissions"
chmod 775 /usr/sbin/ARMiPhoneIAP2
chmod 775 /usr/lib/inject.o

echo "[+] Change the WiFi passphrase"
sed -i "s/wpa_passphrase=.*/wpa_passphrase=$PASSPHRASE/g" /etc/hostapd.conf
