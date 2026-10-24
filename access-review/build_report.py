"""Membuat laporan PDF access review Active Directory dari hasil Export-ADAccessReview.ps1.

Pemakaian:
    python build_report.py --input ad-export --client "PT Contoh" --out laporan.pdf
    python build_report.py --input sample --client "Lab CORP.LAB" --sample --out contoh.pdf
"""
import argparse
import csv
import os
from collections import Counter
from datetime import date

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.lib.utils import ImageReader  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.platypus import (Image, KeepTogether, Paragraph, SimpleDocTemplate,  # noqa: E402
                                Spacer, Table, TableStyle)

# ------------------------------------------------------------------ Gaya
FONT_DIR = "/usr/share/fonts/truetype/google-fonts"
FONTS = {"R": "Poppins-Regular.ttf", "M": "Poppins-Medium.ttf", "B": "Poppins-Bold.ttf"}
for key, file in FONTS.items():
    path = os.path.join(os.environ.get("REPORT_FONT_DIR", FONT_DIR), file)
    if os.path.exists(path):
        pdfmetrics.registerFont(TTFont(f"Body-{key}", path))
    else:  # fallback agar skrip tetap jalan di mesin lain
        FONTS = None
        break
FR, FM, FB = ("Body-R", "Body-M", "Body-B") if FONTS else ("Helvetica", "Helvetica", "Helvetica-Bold")
if FONTS:
    from reportlab.lib.fonts import addMapping
    addMapping("Body-R", 0, 0, "Body-R")
    addMapping("Body-R", 1, 0, "Body-B")
    addMapping("Body-M", 0, 0, "Body-M")
    addMapping("Body-M", 1, 0, "Body-B")

INK = colors.HexColor("#14213D")
MUTED = colors.HexColor("#5B6475")
LINE = colors.HexColor("#E3E6EC")
SOFT = colors.HexColor("#F5F7FA")
ACCENT = colors.HexColor("#2F5BEA")
RISK = {
    "Tinggi": colors.HexColor("#C62828"),
    "Sedang": colors.HexColor("#B26A00"),
    "Rendah": colors.HexColor("#2E7D32"),
    "Info": colors.HexColor("#5B6475"),
}

S = {
    "h1": ParagraphStyle("h1", fontName=FB, fontSize=21, leading=27, textColor=INK, spaceAfter=4),
    "h2": ParagraphStyle("h2", fontName=FB, fontSize=13.5, leading=18, textColor=INK, spaceBefore=12, spaceAfter=6),
    "h3": ParagraphStyle("h3", fontName=FM, fontSize=10.5, leading=14, textColor=INK, spaceBefore=8, spaceAfter=3),
    "body": ParagraphStyle("body", fontName=FR, fontSize=9.2, leading=14, textColor=INK, alignment=TA_LEFT),
    "muted": ParagraphStyle("muted", fontName=FR, fontSize=8.4, leading=12, textColor=MUTED),
    "cell": ParagraphStyle("cell", fontName=FR, fontSize=8.2, leading=11, textColor=INK),
    "cellb": ParagraphStyle("cellb", fontName=FM, fontSize=8.2, leading=11, textColor=INK),
    "kpi": ParagraphStyle("kpi", fontName=FB, fontSize=19, leading=22, textColor=INK),
    "kpil": ParagraphStyle("kpil", fontName=FR, fontSize=7.8, leading=10, textColor=MUTED),
}


def P(text, style="body"):
    return Paragraph(text, S[style])


# ------------------------------------------------------------------ Data
def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def as_int(v):
    try:
        return int(str(v).strip())
    except ValueError:
        return None


def days_since(iso):
    if not iso:
        return None
    try:
        return (date.today() - date.fromisoformat(iso[:10])).days
    except ValueError:
        return None


def is_it(dept):
    d = (dept or "").lower()
    return any(k in d for k in ("it", "teknologi", "infra", "security", "keamanan", "system"))


# Akun bawaan Windows: selalu ada di setiap domain dan dikelola sistem, bukan temuan access review
BUILTIN = {"krbtgt", "guest", "defaultaccount", "wdagutilityaccount"}


def analyze(users, privileged, stale_days, admin_limit, grace_days=14):
    users = [u for u in users if u["Account"].lower() not in BUILTIN and not u["Account"].lower().startswith("krbtgt_")]
    enabled = [u for u in users if truthy(u["Enabled"])]
    disabled = [u for u in users if not truthy(u["Enabled"])]
    has_emptype = any((u.get("EmployeeType") or "").strip() for u in users)

    def stale(u):
        d = as_int(u.get("DaysSinceLogon"))
        return d is not None and d > stale_days

    def never(u):
        created = days_since(u.get("CreatedUtc"))
        return not u.get("LastLogonUtc") and (created is None or created >= grace_days)

    leavers = [u for u in enabled if (u.get("EmployeeType") or "").lower() in ("terminated", "leaver", "resigned")]
    stale_users = [u for u in enabled if stale(u)]
    never_users = [u for u in enabled if never(u)]
    pwd_never = [u for u in enabled if truthy(u.get("PasswordNeverExpires"))]
    disabled_groups = [u for u in disabled if (as_int(u.get("GroupCount")) or 0) > 0]

    priv_enabled = [p for p in privileged if truthy(p["Enabled"])]
    priv_stale = [p for p in priv_enabled
                  if as_int(p.get("DaysSinceLogon")) is not None and as_int(p["DaysSinceLogon"]) > stale_days]
    priv_nonit = [p for p in priv_enabled if p.get("Department") and not is_it(p["Department"])]
    da = {p["Account"] for p in priv_enabled if p["Group"].lower() == "domain admins"}
    priv_disabled = [p for p in privileged if not truthy(p["Enabled"])]

    findings = []

    def add(code, title, items, risk, why, fix, kind="user"):
        count = len({i["Account"] for i in items}) if kind == "priv" else len(items)
        findings.append({"code": code, "title": title, "items": items, "count": count, "risk": risk,
                         "why": why, "fix": fix, "kind": kind})

    if has_emptype:
        add("F1", "Karyawan keluar, akun masih aktif", leavers, "Tinggi",
            "Mantan karyawan masih bisa login ke sistem internal, termasuk dari luar kantor lewat VPN.",
            "Nonaktifkan segera, cabut semua keanggotaan group, dan pastikan proses offboarding "
            "otomatis memicu penonaktifan akun.")
    add("F2", "Akun dari luar departemen IT di group privileged", priv_nonit, "Tinggi",
        "Hak admin di tangan pengguna non-IT memperbesar dampak jika akunnya terkena phishing.",
        "Konfirmasi kebutuhan bisnis dan approval-nya. Jika tidak ada, keluarkan dari group.",
        kind="priv")
    add("F3", f"Akun privileged tidak login > {stale_days} hari", priv_stale, "Tinggi",
        "Akun admin yang tidak dipakai adalah target empuk karena aktivitas mencurigakan jarang disadari.",
        "Nonaktifkan atau keluarkan dari group privileged; gunakan akun admin terpisah yang dipakai aktif.",
        kind="priv")
    add("F4", f"Anggota Domain Admins melebihi {admin_limit} akun", sorted(da) if len(da) > admin_limit else [],
        "Sedang",
        "Semakin banyak Domain Admins, semakin luas permukaan serangan atas seluruh domain.",
        "Terapkan prinsip least privilege: delegasikan hak spesifik lewat group lain, bukan Domain Admins.",
        kind="name")
    add("F5", f"Akun aktif tidak login > {stale_days} hari (stale)", stale_users, "Sedang",
        "Akun yang terlupakan sering luput dari reset password dan pemantauan.",
        "Konfirmasi ke atasan pemilik akun; nonaktifkan yang tidak lagi dibutuhkan, lalu hapus setelah masa tunggu.")
    add("F6", "Akun aktif yang belum pernah login", never_users, "Sedang",
        "Akun dibuat tetapi tidak dipakai; password awalnya sering lemah atau sudah tersebar.",
        "Nonaktifkan jika tidak jelas pemiliknya; tetapkan batas waktu aktivasi untuk akun baru.")
    add("F7", "Password tidak pernah kedaluwarsa", pwd_never, "Sedang",
        "Password yang tidak pernah diganti terus berlaku walaupun pernah bocor.",
        "Aktifkan kedaluwarsa password untuk akun user; untuk akun layanan gunakan gMSA atau rotasi terjadwal.")
    add("F8", "Akun nonaktif yang masih menjadi anggota group", disabled_groups, "Rendah",
        "Jika akun diaktifkan kembali (sengaja atau tidak), seluruh hak aksesnya langsung kembali.",
        "Cabut keanggotaan group saat akun dinonaktifkan sebagai bagian dari prosedur offboarding.")
    if priv_disabled:
        add("F9", "Akun nonaktif di group privileged", priv_disabled, "Rendah",
            "Tidak berbahaya selama nonaktif, tetapi membuat daftar admin sulit diaudit.",
            "Keluarkan dari group privileged.", kind="priv")

    order = {"Tinggi": 0, "Sedang": 1, "Rendah": 2}
    findings.sort(key=lambda f: (f["count"] == 0, order[f["risk"]]))
    stats = {"total": len(users), "enabled": len(enabled), "disabled": len(disabled),
             "priv_accounts": len({p["Account"] for p in priv_enabled}), "domain_admins": len(da),
             "has_emptype": has_emptype}
    return findings, stats, enabled, stale_users


# ------------------------------------------------------------------ Grafik
def dept_chart(enabled, stale_users, path):
    total = Counter((u.get("Department") or "Tanpa departemen") for u in enabled)
    stl = Counter((u.get("Department") or "Tanpa departemen") for u in stale_users)
    depts = [d for d, _ in total.most_common(8)][::-1]
    active_ok = [total[d] - stl[d] for d in depts]
    stale_v = [stl[d] for d in depts]

    plt.rcParams["font.family"] = "Poppins" if FONTS else "DejaVu Sans"
    fig, ax = plt.subplots(figsize=(7.2, 0.34 * len(depts) + 0.8), dpi=200)
    ax.barh(depts, active_ok, color="#2F5BEA", label="Aktif dan dipakai", height=0.62)
    ax.barh(depts, stale_v, left=active_ok, color="#E8A33D", label="Stale", height=0.62)
    for i, d in enumerate(depts):
        ax.text(total[d] + max(total.values()) * 0.01, i, f"{total[d]}  ({stl[d]} stale)",
                va="center", fontsize=8, color="#14213D")
    ax.set_xlim(0, max(total.values()) * 1.25)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#C9CED8")
    ax.tick_params(axis="both", labelsize=8.5, colors="#14213D", length=0)
    ax.xaxis.grid(True, color="#ECEEF2")
    ax.set_axisbelow(True)
    ax.legend(loc="lower right", fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# ------------------------------------------------------------------ PDF
def kpi_row(stats, findings):
    high = sum(f["count"] for f in findings if f["risk"] == "Tinggi")
    tiles = [
        (f"{stats['enabled']}", "Akun aktif"),
        (f"{stats['disabled']}", "Akun nonaktif"),
        (f"{stats['domain_admins']}", "Anggota Domain Admins"),
        (f"{high}", "Temuan risiko tinggi"),
    ]
    data = [[[P(v, "kpi"), P(lbl, "kpil")] for v, lbl in tiles]]
    t = Table(data, colWidths=[42 * mm] * 4, rowHeights=[20 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SOFT),
        ("BOX", (0, 0), (-1, -1), 0, colors.white),
        ("LINEAFTER", (0, 0), (-2, -1), 3, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (3, 0), (3, 0), RISK["Tinggi"]),
    ]))
    if high:
        t.setStyle(TableStyle([("LINEABOVE", (3, 0), (3, 0), 2.5, RISK["Tinggi"])]))
    return t


def risk_badge(risk):
    return Paragraph(f'<font color="{RISK[risk].hexval()}"><b>{risk}</b></font>', S["cell"])


def findings_table(findings):
    head = [P("<b>No</b>", "cellb"), P("<b>Temuan</b>", "cellb"), P("<b>Jumlah</b>", "cellb"),
            P("<b>Risiko</b>", "cellb")]
    rows = [head]
    for f in findings:
        rows.append([P(f["code"], "cell"), P(f["title"], "cell"),
                     P(str(f["count"]) if f["count"] else "0 (aman)", "cell"),
                     risk_badge(f["risk"]) if f["count"] else P("-", "cell")])
    t = Table(rows, colWidths=[12 * mm, 112 * mm, 24 * mm, 20 * mm], repeatRows=1)
    style = [
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, f in enumerate(findings, start=1):
        if f["count"] == 0:
            style.append(("TEXTCOLOR", (0, i), (-1, i), MUTED))
    t.setStyle(TableStyle(style))
    return t


def detail_table(f, limit=25):
    if f["kind"] == "name":
        rows = [[P("<b>Akun</b>", "cellb")]] + [[P(a, "cell")] for a in f["items"][:limit]]
        widths = [168 * mm]
    elif f["kind"] == "priv":
        rows = [[P(f"<b>{h}</b>", "cellb") for h in ("Akun", "Group", "Departemen", "Keanggotaan", "Login terakhir")]]
        for p in f["items"][:limit]:
            rows.append([P(p["Account"], "cell"), P(p["Group"], "cell"), P(p.get("Department") or "-", "cell"),
                         P("Langsung" if p.get("Membership") == "Direct" else "Bersarang", "cell"),
                         P(p.get("LastLogonUtc") or "belum pernah", "cell")])
        widths = [38 * mm, 36 * mm, 32 * mm, 26 * mm, 36 * mm]
    else:
        rows = [[P(f"<b>{h}</b>", "cellb") for h in ("Akun", "Departemen", "Login terakhir", "Dibuat", "Lokasi (OU)")]]
        for u in f["items"][:limit]:
            ou = (u.get("OU") or "").replace("OU=", "").split(",")[0] or "-"
            rows.append([P(u["Account"], "cell"), P(u.get("Department") or "-", "cell"),
                         P(u.get("LastLogonUtc") or "belum pernah", "cell"), P(u.get("CreatedUtc") or "-", "cell"),
                         P(ou, "cell")])
        widths = [42 * mm, 30 * mm, 30 * mm, 26 * mm, 40 * mm]
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SOFT),
        ("LINEBELOW", (0, 0), (-1, -1), 0.35, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def build(args):
    users = read_csv(os.path.join(args.input, "users.csv"))
    privileged = read_csv(os.path.join(args.input, "privileged.csv"))
    if not users:
        raise SystemExit(f"users.csv tidak ditemukan atau kosong di {args.input}")
    findings, stats, enabled, stale_users = analyze(users, privileged, args.stale_days, args.admin_limit, args.grace_days)

    chart = os.path.join(os.path.dirname(os.path.abspath(args.out)), "_dept_chart.png")
    dept_chart(enabled, stale_users, chart)
    iw, ih = ImageReader(chart).getSize()

    def on_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(ACCENT)
        canvas.rect(0, h - 5, w, 5, stroke=0, fill=1)
        canvas.setFont(FR, 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 11 * mm, f"Access Review Active Directory  ·  {args.client}")
        canvas.drawRightString(w - 18 * mm, 11 * mm, f"Halaman {doc.page}")
        if args.sample:
            canvas.setFont(FB, 7.5)
            canvas.setFillColor(RISK["Sedang"])
            canvas.drawRightString(w - 18 * mm, h - 12 * mm, "CONTOH LAPORAN  ·  DATA LAB SIMULASI")
        canvas.restoreState()

    doc = SimpleDocTemplate(args.out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=20 * mm,
                            title=f"Access Review Active Directory - {args.client}", author=args.author)
    story = []
    story += [P("LAPORAN ACCESS REVIEW", "muted"), P("Active Directory", "h1"),
              P(f"{args.client}  ·  Domain {args.domain}  ·  {date.today().strftime('%d-%m-%Y')}", "muted"),
              P(f"Disusun oleh {args.author}", "muted"), Spacer(1, 8 * mm)]
    if args.sample:
        story += [Table([[P("<b>Contoh laporan.</b> Data berasal dari lab Samba AD berisi akun fiktif yang "
                            "dibuat untuk demonstrasi, bukan dari organisasi nyata.", "cell")]],
                        colWidths=[174 * mm],
                        style=[("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF4E0")),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]),
                  Spacer(1, 6 * mm)]

    story += [P("Ringkasan", "h2"), kpi_row(stats, findings), Spacer(1, 5 * mm)]
    active = [f for f in findings if f["count"]]
    high = [f for f in active if f["risk"] == "Tinggi"]
    if high:
        lead = (f"Ditemukan <b>{len(active)} jenis temuan</b>, {len(high)} di antaranya berisiko tinggi. "
                f"Prioritas pertama: <b>{high[0]['title'].lower()}</b> ({high[0]['count']} akun).")
    elif active:
        lead = f"Ditemukan <b>{len(active)} jenis temuan</b>, tidak ada yang berisiko tinggi."
    else:
        lead = "Tidak ditemukan masalah pada pemeriksaan yang dilakukan."
    story += [P(lead), Spacer(1, 2 * mm),
              P(f"Pemeriksaan mencakup {stats['total']} akun user dan keanggotaan group privileged "
                f"(langsung maupun bersarang). Akun dianggap stale jika tidak login lebih dari "
                f"{args.stale_days} hari.", "muted")]
    if not stats["has_emptype"]:
        story.append(P("Catatan: atribut status karyawan (employeeType) tidak terisi, sehingga pemeriksaan "
                       "akun mantan karyawan tidak dapat dilakukan otomatis.", "muted"))

    story += [P("Daftar temuan", "h2"), findings_table(findings),
              KeepTogether([P("Akun aktif per departemen", "h2"),
                            Image(chart, width=160 * mm, height=160 * mm * ih / iw)])]

    story.append(P("Rincian dan rekomendasi", "h2"))
    for f in active:
        block = [P(f'{f["code"]}  ·  {f["title"]}  <font color="{RISK[f["risk"]].hexval()}">({f["risk"]}, '
                   f'{f["count"]} akun)</font>', "h3"),
                 P(f"<b>Mengapa penting:</b> {f['why']}", "body"),
                 P(f"<b>Rekomendasi:</b> {f['fix']}", "body"), Spacer(1, 2 * mm)]
        story.append(KeepTogether(block + [detail_table(f)]))
        if f["count"] > 25:
            story.append(P(f"Menampilkan 25 dari {f['count']} akun. Daftar lengkap tersedia di lampiran CSV.",
                           "muted"))
        story.append(Spacer(1, 4 * mm))

    story += [P("Metode dan batasan", "h2"),
              P("Data diambil dengan skrip PowerShell read-only yang dijalankan oleh tim IT klien menggunakan "
                "akun domain biasa. Tidak ada perubahan yang dilakukan pada Active Directory selama pemeriksaan."),
              Spacer(1, 2 * mm),
              P("Waktu login diambil dari atribut lastLogonTimestamp yang direplikasi setiap 9 sampai 14 hari, "
                "sehingga akurat untuk mendeteksi akun stale tetapi tidak untuk melacak login terakhir secara "
                "presisi. Penilaian departemen non-IT pada group privileged bersifat indikatif dan perlu "
                "dikonfirmasi dengan struktur organisasi klien.", "muted")]

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    os.remove(chart)
    return findings, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="ad-export", help="folder berisi users.csv dan privileged.csv")
    ap.add_argument("--client", default="Klien", help="nama organisasi klien")
    ap.add_argument("--domain", default="-", help="nama domain, misalnya corp.local")
    ap.add_argument("--author", default="Andhika Suryamiharja")
    ap.add_argument("--stale-days", type=int, default=90)
    ap.add_argument("--grace-days", type=int, default=14,
                    help="akun baru yang belum login tidak dihitung sebagai temuan selama N hari pertama")
    ap.add_argument("--admin-limit", type=int, default=5, help="batas wajar jumlah Domain Admins")
    ap.add_argument("--sample", action="store_true", help="tandai sebagai contoh laporan")
    ap.add_argument("--out", default="laporan-access-review.pdf")
    args = ap.parse_args()
    findings, stats = build(args)
    print(f"Laporan dibuat: {args.out}")
    for f in findings:
        print(f"  {f['code']} {f['risk']:6} {f['count']:4}  {f['title']}")


if __name__ == "__main__":
    main()
