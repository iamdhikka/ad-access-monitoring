# Access Review Active Directory

Paket untuk melakukan access review satu kali di Active Directory klien, tanpa membutuhkan akses admin.

1. **`Export-ADAccessReview.ps1`**: dijalankan oleh tim IT klien. Skrip hanya **membaca** data lewat LDAP dan menyimpannya ke CSV.
2. **`build_report.py`**: mengolah CSV menjadi laporan PDF berisi temuan, tingkat risiko, dan rekomendasi.

Contoh hasil: [`contoh-laporan-access-review.pdf`](contoh-laporan-access-review.pdf), dibuat dari data lab Samba AD di repo ini (akun fiktif).

## 1. Ekspor data (di sisi klien)

Kebutuhan: komputer yang sudah join ke domain, akun domain biasa (tidak perlu Domain Admin), dan Windows PowerShell 5.1 atau PowerShell 7. Modul RSAT tidak diperlukan.

```powershell
# Jika eksekusi skrip diblokir, izinkan hanya untuk sesi ini:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\Export-ADAccessReview.ps1                     # standar
.\Export-ADAccessReview.ps1 -Anonymize          # nama akun diganti kode acak
.\Export-ADAccessReview.ps1 -StaleDays 60 -PrivilegedGroups "Domain Admins","Server-Admins"
```

Hasilnya ada di folder `ad-export`: `users.csv`, `privileged.csv`, dan `summary.txt`.

Skrip tidak membuat, mengubah, atau menghapus objek apa pun. Silakan baca kodenya sebelum dijalankan; semua operasinya adalah pencarian LDAP (`DirectorySearcher`).

## 2. Buat laporan

```bash
pip install reportlab matplotlib
python build_report.py --input ad-export --client "PT Contoh" --domain contoh.local --out laporan.pdf
```

Opsi lain: `--stale-days 90`, `--admin-limit 5` (batas wajar jumlah Domain Admins), `--grace-days 14` (akun baru yang belum login tidak langsung dianggap temuan).

## Temuan yang diperiksa

| Kode | Temuan | Risiko |
|---|---|---|
| F1 | Karyawan keluar (`employeeType`), akun masih aktif | Tinggi |
| F2 | Akun dari luar departemen IT di group privileged | Tinggi |
| F3 | Akun privileged tidak login > N hari | Tinggi |
| F4 | Anggota Domain Admins melebihi batas wajar | Sedang |
| F5 | Akun aktif tidak login > N hari (stale) | Sedang |
| F6 | Akun aktif yang belum pernah login | Sedang |
| F7 | Password tidak pernah kedaluwarsa | Sedang |
| F8 | Akun nonaktif yang masih menjadi anggota group | Rendah |
| F9 | Akun nonaktif di group privileged | Rendah |

Keanggotaan group privileged dihitung termasuk group bersarang (`LDAP_MATCHING_RULE_IN_CHAIN`). Akun bawaan Windows (`krbtgt`, `Guest`, dan sejenisnya) dikecualikan dari temuan.

## Batasan

- `lastLogonTimestamp` direplikasi setiap 9–14 hari: akurat untuk akun stale, tidak untuk login terakhir yang presisi.
- F1 hanya bisa dinilai jika organisasi mengisi atribut status karyawan; jika tidak, laporan mencatatnya sebagai batasan.
- F2 memakai nama departemen sebagai indikator dan perlu dikonfirmasi dengan struktur organisasi klien.
