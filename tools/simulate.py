"""Mengisi AD lab dengan organisasi fiktif, lalu mensimulasikan aktivitas identitas sehari-hari:
karyawan baru, karyawan keluar, login, brute force, dan perubahan group privileged."""
import os
import random
import time

import ldap3

from adlib import (BASE_DN, UAC_DISABLED, UAC_DONT_EXPIRE_PASSWORD, UAC_NORMAL, as_int,
                   connect, days_ago, to_filetime)

ADMIN_PW = os.environ["AD_ADMIN_PASSWORD"]
MONITOR_PW = os.environ["AD_MONITOR_PASSWORD"]
SEED_USERS = int(os.environ.get("SEED_USERS", "300"))
INTERVAL = int(os.environ.get("SIM_INTERVAL_SECONDS", "20"))
USER_PW = "Welc0me!Lab-2026"

random.seed(int(os.environ.get("SEED", "42")))

CORP = f"OU=Corp,{BASE_DN}"
OU_USERS = f"OU=Users,{CORP}"
OU_GROUPS = f"OU=Groups,{CORP}"
OU_DISABLED = f"OU=Disabled Users,{CORP}"
OU_SERVICE = f"OU=Service Accounts,{CORP}"
DEPARTMENTS = {"Finance": 0.18, "IT": 0.14, "HR": 0.08, "Operations": 0.35, "Sales": 0.25}
EXTRA_GROUPS = ["VPN-Users", "Server-Admins", "Finance-Approvers"]
DOMAIN_ADMINS = f"CN=Domain Admins,CN=Users,{BASE_DN}"

FIRST = ["Andi", "Budi", "Citra", "Dewi", "Eka", "Fajar", "Gita", "Hendra", "Indah", "Joko", "Kartika",
         "Lestari", "Made", "Nadia", "Oki", "Putri", "Rizky", "Sari", "Taufik", "Utami", "Wahyu", "Yogi",
         "Ayu", "Bayu", "Dimas", "Fitri", "Galih", "Hana", "Irfan", "Lina", "Rina", "Tono", "Wulan"]
LAST = ["Pratama", "Saputra", "Wijaya", "Santoso", "Kusuma", "Hidayat", "Nugroho", "Lestari", "Siregar",
        "Wibowo", "Setiawan", "Gunawan", "Hakim", "Rahman", "Simanjuntak", "Purnomo", "Halim", "Utomo"]

used_names = set()


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def group_dn(name):
    return f"CN={name},{OU_GROUPS}"


def pw(value):
    return f'"{value}"'.encode("utf-16-le")


def new_identity():
    while True:
        first, last = random.choice(FIRST), random.choice(LAST)
        sam = f"{first}.{last}".lower()
        n = 2
        while sam in used_names:
            sam = f"{first}.{last}{n}".lower()
            n += 1
        used_names.add(sam)
        return first, last, sam


def ensure(conn, dn, classes, attrs=None):
    if not conn.add(dn, classes, attrs or {}) and conn.result["result"] != 68:  # 68 = sudah ada
        raise RuntimeError(f"Gagal membuat {dn}: {conn.result['message']}")


def create_user(conn, dept, uac=UAC_NORMAL, ou=None, employee_type="Employee", last_logon_days=None,
                description=None):
    for _ in range(20):  # nama bisa bentrok dengan akun yang sudah ada: coba nama lain
        first, last, sam = new_identity()
        dn = f"CN={first} {last} ({sam}),{ou or f'OU={dept},{OU_USERS}'}"
        attrs = {
            "sAMAccountName": sam, "userPrincipalName": f"{sam}@{BASE_DN.replace('DC=', '').replace(',', '.')}",
            "givenName": first, "sn": last, "displayName": f"{first} {last}",
            "department": dept, "employeeType": employee_type,
            "unicodePwd": pw(USER_PW), "userAccountControl": str(uac),
        }
        if description:
            attrs["description"] = description
        if conn.add(dn, ["top", "person", "organizationalPerson", "user"], attrs):
            break
        if "already in use" not in conn.result["message"] and conn.result["result"] != 68:
            raise RuntimeError(f"Gagal membuat user {sam}: {conn.result['message']}")
    else:
        raise RuntimeError("Tidak menemukan nama user yang belum dipakai")
    if last_logon_days is not None:
        conn.modify(dn, {"lastLogonTimestamp": [(ldap3.MODIFY_REPLACE, [to_filetime(days_ago(last_logon_days))])]})
    return dn


def add_members(conn, group, members):
    for i in range(0, len(members), 200):
        conn.modify(group, {"member": [(ldap3.MODIFY_ADD, members[i:i + 200])]})


def pick_dept():
    return random.choices(list(DEPARTMENTS), weights=list(DEPARTMENTS.values()))[0]


def seed(conn):
    log("Membuat struktur OU dan group")
    ensure(conn, CORP, ["top", "organizationalUnit"])
    for ou in (OU_USERS, OU_GROUPS, OU_DISABLED, OU_SERVICE):
        ensure(conn, ou, ["top", "organizationalUnit"])
    for dept in DEPARTMENTS:
        ensure(conn, f"OU={dept},{OU_USERS}", ["top", "organizationalUnit"])
    for g in [f"GRP-{d}" for d in DEPARTMENTS] + EXTRA_GROUPS:
        ensure(conn, group_dn(g), ["top", "group"], {"sAMAccountName": g, "groupType": "-2147483646"})

    log(f"Membuat {SEED_USERS} user dengan kondisi yang beragam")
    members = {g: [] for g in [f"GRP-{d}" for d in DEPARTMENTS] + EXTRA_GROUPS}
    it_users = []
    for i in range(SEED_USERS):
        dept = pick_dept()
        roll = random.random()
        if roll < 0.08:      # sudah keluar & sudah dinonaktifkan; sebagian masih punya group
            dn = create_user(conn, dept, UAC_NORMAL | UAC_DISABLED, OU_DISABLED, "Terminated",
                             random.randint(30, 400))
            if random.random() < 0.35:
                members[f"GRP-{dept}"].append(dn)
            continue
        if roll < 0.10:      # sudah keluar menurut HR, tapi akun masih aktif (leaver)
            dn = create_user(conn, dept, employee_type="Terminated", last_logon_days=random.randint(20, 90))
        elif roll < 0.18:    # stale: aktif tapi lama tidak login
            dn = create_user(conn, dept, last_logon_days=random.randint(95, 420), description="inactive")
        elif roll < 0.22:    # tidak pernah login
            dn = create_user(conn, dept, description="inactive")
        else:                # aktif normal
            uac = UAC_NORMAL | (UAC_DONT_EXPIRE_PASSWORD if random.random() < 0.06 else 0)
            dn = create_user(conn, dept, uac, last_logon_days=random.uniform(0, 14))
        members[f"GRP-{dept}"].append(dn)
        if random.random() < 0.6:
            members["VPN-Users"].append(dn)
        if dept == "Finance" and random.random() < 0.15:
            members["Finance-Approvers"].append(dn)
        if dept == "IT":
            it_users.append(dn)
        if (i + 1) % 50 == 0:
            log(f"  {i + 1}/{SEED_USERS} user")

    for g, dns in members.items():
        add_members(conn, group_dn(g), dns)
    random.shuffle(it_users)
    add_members(conn, group_dn("Server-Admins"), it_users[:4])
    add_members(conn, DOMAIN_ADMINS, it_users[:2])

    # Dibuat paling akhir: exporter baru bisa login setelah seeding selesai,
    # sehingga 300 user awal tidak terhitung sebagai "karyawan baru".
    log("Membuat akun layanan svc-monitor (read-only, untuk exporter)")
    ensure(conn, f"CN=svc-monitor,{OU_SERVICE}", ["top", "person", "organizationalPerson", "user"], {
        "sAMAccountName": "svc-monitor", "description": "Monitoring - read only",
        "unicodePwd": pw(MONITOR_PW), "userAccountControl": str(UAC_NORMAL | UAC_DONT_EXPIRE_PASSWORD)})
    log("Seeding selesai")


def search_users(conn, extra_filter=""):
    conn.search(f"OU=Users,{CORP}",
                f"(&(objectCategory=person)(objectClass=user){extra_filter})",
                attributes=["sAMAccountName", "department", "employeeType", "userAccountControl", "memberOf"])
    return list(conn.entries)


def active_employees(conn):
    return search_users(conn, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(employeeType=Employee)")


def ev_logins(conn):
    # Akun yang memang dibuat "tidak aktif" (stale / belum pernah login) tidak ikut login
    users = search_users(conn, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(employeeType=Employee)"
                               "(!(description=inactive))")
    for u in random.sample(users, min(8, len(users))):
        conn.modify(u.entry_dn, {"lastLogonTimestamp": [(ldap3.MODIFY_REPLACE, [to_filetime(days_ago(0))])]})


def ev_new_hire(conn):
    dept = pick_dept()
    dn = create_user(conn, dept)
    add_members(conn, group_dn(f"GRP-{dept}"), [dn])
    add_members(conn, group_dn("VPN-Users"), [dn])
    log(f"[provisioning] karyawan baru di {dept}: {dn.split(',')[0][3:]}")


def ev_leaver(conn):
    users = active_employees(conn)
    if not users:
        return
    u = random.choice(users)
    sam = u.sAMAccountName.value
    conn.modify(u.entry_dn, {"employeeType": [(ldap3.MODIFY_REPLACE, ["Terminated"])]})
    if random.random() < 0.2:
        log(f"[leaver] HR menandai {sam} keluar, tapi akunnya LUPA dinonaktifkan")
        return
    deprovision(conn, u)
    log(f"[deprovisioning] {sam} keluar: dinonaktifkan, group dicabut, dipindah ke Disabled Users")


def deprovision(conn, u):
    uac = as_int(u.userAccountControl.value, UAC_NORMAL) | UAC_DISABLED
    conn.modify(u.entry_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [str(uac)])]})
    for g in u.memberOf.values:
        conn.modify(g, {"member": [(ldap3.MODIFY_DELETE, [u.entry_dn])]})
    conn.modify_dn(u.entry_dn, u.entry_dn.split(",")[0], new_superior=OU_DISABLED)


def ev_fix_leaver(conn):
    leftovers = search_users(conn, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(employeeType=Terminated)")
    if leftovers:
        u = random.choice(leftovers)
        deprovision(conn, u)
        log(f"[remediasi] akun leaver {u.sAMAccountName.value} akhirnya dinonaktifkan")


TEMP_ADMIN = "Temporary admin access"


def ev_privileged_change(conn):
    """Akses admin sementara: ditambahkan, lalu dicabut lagi pada event berikutnya.
    Penanda disimpan di atribut description sehingga tetap konsisten walau simulator restart."""
    conn.search(DOMAIN_ADMINS, "(objectClass=group)", search_scope=ldap3.BASE, attributes=["member"])
    current = set(conn.entries[0].member.values) if conn.entries else set()
    conn.search(BASE_DN, f"(&(objectClass=user)(description={TEMP_ADMIN}))", attributes=["sAMAccountName"])
    temp = [e for e in conn.entries if e.entry_dn in current]
    if temp:
        e = temp[0]
        conn.modify(DOMAIN_ADMINS, {"member": [(ldap3.MODIFY_DELETE, [e.entry_dn])]})
        conn.modify(e.entry_dn, {"description": [(ldap3.MODIFY_DELETE, [])]})
        log(f"[privileged] {e.sAMAccountName.value} dikeluarkan dari Domain Admins")
        return
    pool = search_users(conn, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(employeeType=Employee)"
                              "(!(description=*))")
    candidates = [u for u in pool if u.entry_dn not in current]
    if candidates:
        u = random.choice(candidates)
        conn.modify(DOMAIN_ADMINS, {"member": [(ldap3.MODIFY_ADD, [u.entry_dn])]})
        conn.modify(u.entry_dn, {"description": [(ldap3.MODIFY_REPLACE, [TEMP_ADMIN])]})
        log(f"[privileged] {u.sAMAccountName.value} ({u.department.value}) DITAMBAHKAN ke Domain Admins")


def wrong_passwords(conn, sam, attempts=6):
    upn = f"{sam}@{BASE_DN.replace('DC=', '').replace(',', '.')}"
    for i in range(attempts):
        ldap3.Connection(conn.server, user=upn, password=f"tebak-{i}").bind()


def ev_bruteforce(conn):
    users = active_employees(conn)
    if users:
        sam = random.choice(users).sAMAccountName.value
        wrong_passwords(conn, sam)
        log(f"[security] 6x salah password untuk {sam}: akun terkunci")


def ev_password_spray(conn):
    users = active_employees(conn)
    targets = random.sample(users, min(4, len(users)))
    for u in targets:
        wrong_passwords(conn, u.sAMAccountName.value)
    log(f"[security] password spraying: {len(targets)} akun terkunci sekaligus")


def main():
    conn = connect("Administrator", ADMIN_PW)
    conn.search(BASE_DN, "(sAMAccountName=svc-monitor)")
    if not conn.entries:
        seed(conn)
    else:
        log("Data sudah ada, lanjut simulasi")
    conn.search(BASE_DN, "(&(objectCategory=person)(objectClass=user))", attributes=["sAMAccountName"])
    used_names.update(e.sAMAccountName.value.lower() for e in conn.entries)

    # Peluang tiap event per putaran (default 1 putaran = 20 detik)
    events = [(ev_logins, 1.0), (ev_new_hire, 0.35), (ev_leaver, 0.25), (ev_fix_leaver, 0.04),
              (ev_privileged_change, 0.05), (ev_bruteforce, 0.015), (ev_password_spray, 0.006)]
    log(f"Simulasi berjalan setiap {INTERVAL} detik")
    while True:
        time.sleep(INTERVAL)
        try:
            if not conn.bound:
                conn = connect("Administrator", ADMIN_PW)
            for fn, prob in events:
                if random.random() < prob:
                    fn(conn)
        except Exception as exc:
            log(f"[warn] {exc}; mencoba lagi")
            conn = connect("Administrator", ADMIN_PW)


if __name__ == "__main__":
    main()
