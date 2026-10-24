<#
.SYNOPSIS
    Ekspor data akun Active Directory untuk access review. HANYA MEMBACA (read-only).

.DESCRIPTION
    Skrip ini membaca atribut akun user dan keanggotaan group privileged lewat LDAP,
    lalu menyimpannya ke file CSV. Skrip TIDAK mengubah, membuat, atau menghapus apa pun.

    Kebutuhan:
      - Komputer yang sudah join ke domain
      - Akun domain biasa (tidak perlu Domain Admin)
      - Windows PowerShell 5.1 atau PowerShell 7 (tidak perlu modul RSAT/ActiveDirectory)

    Hasil (di folder -OutputDir):
      users.csv       satu baris per akun user
      privileged.csv  anggota group privileged (langsung maupun nested)
      summary.txt     ringkasan jumlah temuan

.PARAMETER OutputDir
    Folder tujuan hasil ekspor. Default: .\ad-export

.PARAMETER StaleDays
    Batas hari tanpa login untuk dianggap stale. Default: 90

.PARAMETER PrivilegedGroups
    Daftar nama group (sAMAccountName) yang dianggap privileged.

.PARAMETER Anonymize
    Ganti nama akun dengan kode acak yang konsisten (misalnya user-3fa91c0b2e),
    dan kosongkan nama tampilan. Departemen tetap dipertahankan untuk analisis.

.EXAMPLE
    .\Export-ADAccessReview.ps1
.EXAMPLE
    .\Export-ADAccessReview.ps1 -Anonymize -StaleDays 60
.EXAMPLE
    .\Export-ADAccessReview.ps1 -PrivilegedGroups "Domain Admins","Server-Admins","VPN-Admins"
#>
[CmdletBinding()]
param(
    [string]$OutputDir = ".\ad-export",
    [int]$StaleDays = 90,
    [string[]]$PrivilegedGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
        "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
        "Group Policy Creator Owners", "DnsAdmins"
    ),
    [switch]$Anonymize
)

$ErrorActionPreference = "Stop"

# Bit userAccountControl
$UAC_DISABLED = 0x0002
$UAC_DONT_EXPIRE_PASSWORD = 0x10000

$now = [DateTime]::UtcNow
$salt = [Guid]::NewGuid().ToString()   # acak per eksekusi: kode anonim tidak bisa ditebak dari nama

function Get-Prop {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return $Result.Properties[$Name][0]
    }
    return $null
}

function Convert-FileTime {
    param($Value)
    if ($null -eq $Value) { return $null }
    $n = [int64]$Value
    if ($n -le 0 -or $n -eq [int64]::MaxValue) { return $null }
    return [DateTime]::FromFileTimeUtc($n)
}

function Get-AccountLabel {
    param([string]$Account)
    if (-not $Anonymize) { return $Account }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($salt + $Account.ToLowerInvariant()))
    $hex = -join ($bytes[0..4] | ForEach-Object { $_.ToString("x2") })
    return "user-$hex"
}

function Get-OU {
    param([string]$DistinguishedName)
    # Ambil bagian setelah CN pertama, tanpa komponen DC=
    $parts = $DistinguishedName -split '(?<!\\),'
    $ous = $parts | Select-Object -Skip 1 | Where-Object { $_ -notlike "DC=*" }
    return ($ous -join ",")
}

function New-Searcher {
    param([string]$Filter, [string[]]$Properties)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$baseDN")
    $s.Filter = $Filter
    $s.PageSize = 1000
    $s.SearchScope = "Subtree"
    [void]$s.PropertiesToLoad.AddRange($Properties)
    return $s
}

Write-Host "Membaca informasi domain..."
$rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$baseDN = [string]$rootDse.Properties["defaultNamingContext"][0]
$domainName = ($baseDN -replace '^DC=', '' -replace ',DC=', '.')
Write-Host "Domain: $domainName"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# ---------------------------------------------------------------- Akun user
Write-Host "Membaca akun user (read-only)..."
$userProps = @("samaccountname", "displayname", "department", "title", "employeetype",
               "useraccountcontrol", "lastlogontimestamp", "pwdlastset", "whencreated",
               "memberof", "distinguishedname")
$searcher = New-Searcher -Filter "(&(objectCategory=person)(objectClass=user))" -Properties $userProps
$results = $searcher.FindAll()

$users = New-Object System.Collections.Generic.List[object]
$byDn = @{}
foreach ($r in $results) {
    $sam = [string](Get-Prop $r "samaccountname")
    $dn = [string](Get-Prop $r "distinguishedname")
    $uac = [int](Get-Prop $r "useraccountcontrol")
    $lastLogon = Convert-FileTime (Get-Prop $r "lastlogontimestamp")
    $pwdLastSet = Convert-FileTime (Get-Prop $r "pwdlastset")
    $created = Get-Prop $r "whencreated"
    $groupCount = 0
    if ($r.Properties.Contains("memberof")) { $groupCount = $r.Properties["memberof"].Count }

    $daysSinceLogon = ""
    if ($null -ne $lastLogon) { $daysSinceLogon = [int]($now - $lastLogon).TotalDays }

    $displayName = [string](Get-Prop $r "displayname")
    if ($Anonymize) { $displayName = "" }

    $row = [PSCustomObject]@{
        Account              = Get-AccountLabel $sam
        DisplayName          = $displayName
        Department           = [string](Get-Prop $r "department")
        Title                = [string](Get-Prop $r "title")
        EmployeeType         = [string](Get-Prop $r "employeetype")
        Enabled              = -not ($uac -band $UAC_DISABLED)
        PasswordNeverExpires = [bool]($uac -band $UAC_DONT_EXPIRE_PASSWORD)
        LastLogonUtc         = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd") } else { "" }
        DaysSinceLogon       = $daysSinceLogon
        PasswordLastSetUtc   = if ($pwdLastSet) { $pwdLastSet.ToString("yyyy-MM-dd") } else { "" }
        CreatedUtc           = if ($created) { ([DateTime]$created).ToUniversalTime().ToString("yyyy-MM-dd") } else { "" }
        GroupCount           = $groupCount
        OU                   = Get-OU $dn
    }
    $users.Add($row)
    $byDn[$dn.ToLowerInvariant()] = @{ Row = $row; MemberOf = @($r.Properties["memberof"]) }
}
$results.Dispose()
$users | Export-Csv -Path (Join-Path $OutputDir "users.csv") -NoTypeInformation -Encoding UTF8
Write-Host ("  {0} akun user diekspor" -f $users.Count)

# ---------------------------------------------------------------- Group privileged
Write-Host "Membaca keanggotaan group privileged (termasuk nested)..."
$privileged = New-Object System.Collections.Generic.List[object]
foreach ($group in $PrivilegedGroups) {
    $escaped = $group -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
    $gs = New-Searcher -Filter "(&(objectClass=group)(sAMAccountName=$escaped))" -Properties @("distinguishedname")
    $g = $gs.FindOne()
    if ($null -eq $g) {
        Write-Host "  (lewati) group '$group' tidak ditemukan"
        continue
    }
    $groupDn = [string](Get-Prop $g "distinguishedname")
    $groupDnEsc = $groupDn -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'

    # LDAP_MATCHING_RULE_IN_CHAIN: semua user yang menjadi anggota, langsung maupun lewat group bersarang
    $ms = New-Searcher -Filter "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$groupDnEsc))" -Properties @("distinguishedname")
    $members = $ms.FindAll()
    foreach ($m in $members) {
        $mdn = ([string](Get-Prop $m "distinguishedname")).ToLowerInvariant()
        if (-not $byDn.ContainsKey($mdn)) { continue }
        $info = $byDn[$mdn]
        $direct = $false
        foreach ($mo in $info.MemberOf) { if ($mo -ieq $groupDn) { $direct = $true; break } }
        $privileged.Add([PSCustomObject]@{
            Group          = $group
            Account        = $info.Row.Account
            Department     = $info.Row.Department
            Enabled        = $info.Row.Enabled
            Membership     = if ($direct) { "Direct" } else { "Nested" }
            LastLogonUtc   = $info.Row.LastLogonUtc
            DaysSinceLogon = $info.Row.DaysSinceLogon
        })
    }
    $members.Dispose()
}
$privileged | Export-Csv -Path (Join-Path $OutputDir "privileged.csv") -NoTypeInformation -Encoding UTF8
Write-Host ("  {0} keanggotaan privileged diekspor" -f $privileged.Count)

# ---------------------------------------------------------------- Ringkasan
$enabled = @($users | Where-Object { $_.Enabled })
$stale = @($enabled | Where-Object { $_.DaysSinceLogon -ne "" -and [int]$_.DaysSinceLogon -gt $StaleDays })
$never = @($enabled | Where-Object { $_.LastLogonUtc -eq "" })
$pwdNever = @($enabled | Where-Object { $_.PasswordNeverExpires })

$summary = @"
Ringkasan ekspor Active Directory (read-only)
Domain           : $domainName
Waktu ekspor UTC : $($now.ToString("yyyy-MM-dd HH:mm"))
Anonimisasi      : $([bool]$Anonymize)
Batas stale      : $StaleDays hari

Akun user total              : $($users.Count)
Akun aktif                   : $($enabled.Count)
Akun nonaktif                : $($users.Count - $enabled.Count)
Aktif, stale > $StaleDays hari      : $($stale.Count)
Aktif, belum pernah login    : $($never.Count)
Aktif, password never expires: $($pwdNever.Count)
Keanggotaan group privileged : $($privileged.Count)

Catatan: lastLogonTimestamp direplikasi setiap 9-14 hari, sehingga cocok untuk
mendeteksi akun stale, bukan untuk melacak login terakhir secara presisi.
"@
$summary | Out-File -FilePath (Join-Path $OutputDir "summary.txt") -Encoding UTF8
Write-Host ""
Write-Host $summary
Write-Host "Selesai. Kirimkan isi folder '$OutputDir' (users.csv, privileged.csv, summary.txt)."
