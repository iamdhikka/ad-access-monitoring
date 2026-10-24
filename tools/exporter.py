"""Prometheus exporter untuk kebersihan akses Active Directory.

Membaca AD lewat LDAPS memakai akun read-only, lalu mengekspos metrik di :9300/metrics.
Event provisioning/deprovisioning dan perubahan group privileged dihitung dengan
membandingkan kondisi antar-polling, sehingga tren bisa dilihat di Grafana."""
import os
import time
from prometheus_client import Counter, Gauge, start_http_server

from adlib import (BASE_DN, UAC_DISABLED, UAC_DONT_EXPIRE_PASSWORD, UAC_LOCKOUT, as_datetime, as_int,
                   connect, days_ago)

MONITOR_USER = os.environ.get("AD_MONITOR_USER", "svc-monitor")
MONITOR_PW = os.environ["AD_MONITOR_PASSWORD"]
INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))
STALE_DAYS = int(os.environ.get("STALE_DAYS", "90"))
PRIVILEGED_GROUPS = [g.strip() for g in os.environ.get(
    "PRIVILEGED_GROUPS", "Domain Admins,Enterprise Admins,Schema Admins,Server-Admins").split(",")]

up = Gauge("ad_up", "1 jika polling AD terakhir berhasil")
poll_seconds = Gauge("ad_poll_duration_seconds", "Durasi polling AD terakhir")
last_success = Gauge("ad_last_success_timestamp_seconds", "Waktu polling AD terakhir yang berhasil")

users = Gauge("ad_users", "Jumlah akun user per status", ["status"])
users_dept = Gauge("ad_users_enabled_by_department", "Akun aktif per departemen", ["department"])
stale = Gauge("ad_users_stale", f"Akun aktif yang tidak login lebih dari STALE_DAYS hari", ["days"])
never = Gauge("ad_users_never_logged_on", "Akun aktif yang belum pernah login")
pw_never_expires = Gauge("ad_users_password_never_expires", "Akun aktif dengan password tidak pernah kedaluwarsa")
leavers = Gauge("ad_users_terminated_still_enabled", "Karyawan keluar (employeeType=Terminated) yang akunnya masih aktif")
disabled_with_groups = Gauge("ad_users_disabled_with_group_membership", "Akun nonaktif yang masih menjadi anggota group")
priv_members = Gauge("ad_privileged_group_members", "Jumlah anggota langsung group privileged", ["group"])
priv_member_info = Gauge("ad_privileged_group_member_info", "Anggota group privileged (1 = anggota)",
                         ["group", "member", "department"])

lifecycle = Counter("ad_account_lifecycle_events", "Event siklus hidup akun yang terdeteksi", ["event"])
priv_changes = Counter("ad_privileged_group_changes", "Perubahan keanggotaan group privileged", ["group", "action"])

previous = {"accounts": None, "privileged": None}


def poll(conn):
    conn.search(BASE_DN, "(&(objectCategory=person)(objectClass=user)(!(isCriticalSystemObject=TRUE)))",
                attributes=["sAMAccountName", "userAccountControl", "msDS-User-Account-Control-Computed",
                            "lastLogonTimestamp", "department", "employeeType", "memberOf", "description"],
                paged_size=500)
    entries = [e for e in conn.entries if "svc-" not in str(e.sAMAccountName.value)]

    stale_cutoff = days_ago(STALE_DAYS)
    counts = {"enabled": 0, "disabled": 0, "locked": 0}
    dept_counts = {}
    n_stale = n_never = n_pw = n_leaver = n_disabled_groups = 0
    accounts = {}
    by_dn = {}

    for e in entries:
        sam = str(e.sAMAccountName.value)
        uac = as_int(e.userAccountControl.value)
        computed = as_int(e["msDS-User-Account-Control-Computed"].value)
        enabled = not uac & UAC_DISABLED
        accounts[sam] = enabled
        dept = str(e.department.value or "Unknown")
        by_dn[e.entry_dn.lower()] = (sam, dept)

        if not enabled:
            counts["disabled"] += 1
            if e.memberOf.values:
                n_disabled_groups += 1
            continue
        counts["enabled"] += 1
        dept_counts[dept] = dept_counts.get(dept, 0) + 1
        if computed & UAC_LOCKOUT:
            counts["locked"] += 1
        if uac & UAC_DONT_EXPIRE_PASSWORD:
            n_pw += 1
        if str(e.employeeType.value or "") == "Terminated":
            n_leaver += 1
        last = as_datetime(e.lastLogonTimestamp.value)
        if last is None:
            n_never += 1
        elif last < stale_cutoff:
            n_stale += 1

    for status, value in counts.items():
        users.labels(status).set(value)
    users_dept.clear()
    for dept, value in dept_counts.items():
        users_dept.labels(dept).set(value)
    stale.labels(str(STALE_DAYS)).set(n_stale)
    never.set(n_never)
    pw_never_expires.set(n_pw)
    leavers.set(n_leaver)
    disabled_with_groups.set(n_disabled_groups)

    # Group privileged (keanggotaan langsung)
    privileged = {}
    for group in PRIVILEGED_GROUPS:
        conn.search(BASE_DN, f"(&(objectClass=group)(sAMAccountName={group}))", attributes=["member"])
        if not conn.entries:
            continue
        members = {str(m).lower() for m in conn.entries[0].member.values}
        privileged[group] = members
    priv_member_info.clear()
    for group, members in privileged.items():
        priv_members.labels(group).set(len(members))
        for dn in members:
            sam, dept = by_dn.get(dn, (dn.split(",")[0][3:], "-"))
            priv_member_info.labels(group, sam, dept).set(1)

    # Event: bandingkan dengan polling sebelumnya (polling pertama = baseline)
    before = previous["accounts"]
    if before is not None:
        for sam, enabled in accounts.items():
            if sam not in before:
                lifecycle.labels("created").inc()
            elif before[sam] and not enabled:
                lifecycle.labels("disabled").inc()
            elif not before[sam] and enabled:
                lifecycle.labels("enabled").inc()
        for sam in before.keys() - accounts.keys():
            lifecycle.labels("deleted").inc()
    if previous["privileged"] is not None:
        for group, members in privileged.items():
            old = previous["privileged"].get(group, set())
            for _ in members - old:
                priv_changes.labels(group, "added").inc()
            for _ in old - members:
                priv_changes.labels(group, "removed").inc()
    previous["accounts"] = accounts
    previous["privileged"] = privileged


def main():
    port = int(os.environ.get("EXPORTER_PORT", "9300"))
    start_http_server(port)
    # Inisialisasi seri counter supaya grafik dan increase() langsung punya titik nol
    for event in ("created", "disabled", "enabled", "deleted"):
        lifecycle.labels(event)
    for group in PRIVILEGED_GROUPS:
        for action in ("added", "removed"):
            priv_changes.labels(group, action)
    print(f"Exporter berjalan di :{port}, polling setiap {INTERVAL} detik", flush=True)

    conn = None
    while True:
        start = time.time()
        try:
            if conn is None or not conn.bound:
                conn = connect(MONITOR_USER, MONITOR_PW, retries=1)
            poll(conn)
            up.set(1)
            last_success.set(time.time())
        except Exception as exc:
            print(f"[warn] polling gagal: {exc}", flush=True)
            up.set(0)
            conn = None
        poll_seconds.set(time.time() - start)
        time.sleep(max(1, INTERVAL - (time.time() - start)))


if __name__ == "__main__":
    main()
