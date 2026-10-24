"""Koneksi LDAPS ke Active Directory dan helper waktu AD (FILETIME)."""
import os
import ssl
import time
from datetime import datetime, timedelta, timezone

import ldap3

AD_HOST = os.environ.get("AD_HOST", "dc1.corp.lab")
AD_REALM = os.environ.get("AD_REALM", "CORP.LAB").lower()
BASE_DN = ",".join(f"DC={p}" for p in AD_REALM.split("."))
CA_FILE = os.environ.get("AD_CA_FILE", "/tls/ca.crt")

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Bit userAccountControl
UAC_DISABLED = 0x0002
UAC_NORMAL = 0x0200
UAC_DONT_EXPIRE_PASSWORD = 0x10000
# Bit msDS-User-Account-Control-Computed
UAC_LOCKOUT = 0x0010


def server():
    # Sertifikat DC selalu diverifikasi terhadap CA lab: tidak ada "validate=CERT_NONE".
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=CA_FILE)
    return ldap3.Server(AD_HOST, port=636, use_ssl=True, tls=tls, connect_timeout=5)


def connect(user, password, retries=60, wait=5):
    """Bind ke AD; tunggu sampai DC siap (berguna saat stack baru dinyalakan)."""
    upn = user if "@" in user else f"{user}@{AD_REALM}"
    last = None
    for _ in range(retries):
        try:
            conn = ldap3.Connection(server(), user=upn, password=password, auto_bind=True,
                                    receive_timeout=30)
            return conn
        except Exception as exc:  # DC belum siap, sertifikat belum ada, dsb.
            last = exc
            time.sleep(wait)
    raise RuntimeError(f"Tidak bisa terhubung ke {AD_HOST}: {last}")


def to_filetime(dt):
    return str(int((dt - EPOCH_1601).total_seconds() * 10_000_000))


def days_ago(days):
    return datetime.now(timezone.utc) - timedelta(days=days)


def as_datetime(value):
    """ldap3 mengembalikan datetime, list kosong, atau angka; seragamkan ke datetime/None."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        return None if value <= EPOCH_1601 + timedelta(days=1) else value
    try:
        num = int(value)
    except (TypeError, ValueError):
        return None
    if num <= 0:
        return None
    return EPOCH_1601 + timedelta(microseconds=num / 10)


def as_int(value, default=0):
    if isinstance(value, list):
        value = value[0] if value else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
