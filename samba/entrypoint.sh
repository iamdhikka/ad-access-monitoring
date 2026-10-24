#!/bin/bash
# Domain controller Samba AD untuk lab.
# Run pertama: buat CA + sertifikat LDAPS, provision domain, atur kebijakan lockout.
# Run berikutnya: langsung menjalankan DC dari data yang tersimpan di volume.
set -euo pipefail

DATA="${SAMBA_DATA_DIR:-/samba}"
TLS="${TLS_DIR:-/tls}"
HOST="${AD_HOSTNAME:-dc1}"
REALM="${AD_REALM:-CORP.LAB}"
DOMAIN="${AD_DOMAIN:-CORP}"
FQDN="${HOST}.${REALM,,}"

if [ ! -f "$TLS/ca.crt" ]; then
  echo "[dc] Membuat CA lab dan sertifikat LDAPS untuk $FQDN"
  mkdir -p "$TLS"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$TLS/ca.key" -out "$TLS/ca.crt" -subj "/CN=${DOMAIN} Lab Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout "$TLS/dc.key" -out "$TLS/dc.csr" -subj "/CN=$FQDN" 2>/dev/null
  printf '%s\n' \
    "subjectAltName=DNS:$FQDN,DNS:$HOST" \
    "basicConstraints=CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" \
    "authorityKeyIdentifier=keyid,issuer" \
    "subjectKeyIdentifier=hash" > "$TLS/dc.ext"
  openssl x509 -req -in "$TLS/dc.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
    -days 825 -extfile "$TLS/dc.ext" -out "$TLS/dc.crt" 2>/dev/null
  chmod 600 "$TLS/dc.key" "$TLS/ca.key"
  chmod 644 "$TLS/ca.crt" "$TLS/dc.crt"
fi

if [ ! -f "$DATA/private/sam.ldb" ]; then
  echo "[dc] Provisioning domain $REALM"
  mkdir -p "$DATA"
  # xattr_tdb: menyimpan ACL di file tdb, sehingga container tidak butuh mode privileged
  samba-tool domain provision \
    --targetdir="$DATA" --host-name="$HOST" \
    --realm="$REALM" --domain="$DOMAIN" \
    --server-role=dc --dns-backend=SAMBA_INTERNAL --use-rfc2307 \
    --adminpass="$AD_ADMIN_PASSWORD" \
    --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
    --option="tls enabled = yes" \
    --option="tls keyfile = $TLS/dc.key" \
    --option="tls certfile = $TLS/dc.crt" \
    --option="tls cafile = $TLS/ca.crt" > /tmp/provision.log 2>&1 \
    || { cat /tmp/provision.log; exit 1; }

  # Kebijakan lockout: 5 kali salah password -> terkunci 30 menit
  samba-tool domain passwordsettings set -H "$DATA/private/sam.ldb" \
    --account-lockout-threshold=5 --account-lockout-duration=30 --reset-account-lockout-after=30 >/dev/null
  echo "[dc] Provisioning selesai"
fi

echo "[dc] Menjalankan domain controller $FQDN"
exec samba -i -s "$DATA/etc/smb.conf" -d 1
