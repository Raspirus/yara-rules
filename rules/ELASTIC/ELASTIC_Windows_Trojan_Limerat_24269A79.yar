rule ELASTIC_Windows_Trojan_Limerat_24269A79 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Limerat (Windows.Trojan.Limerat)"
		author = "Elastic Security"
		id = "24269a79-0172-4da5-9b4d-f61327072bf0"
		date = "2021-08-17"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Limerat.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ec781a714d6bc6fac48d59890d9ae594ffd4dbc95710f2da1f1aa3d5b87b9e01"
		logic_hash = "053a6abe589db23c4b9baed24729c8bcdd9019535fd0d9efc60ab4035c9779f3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cb714cd787519216d25edaad9f89a9c0ce1b8fbbbcdf90bda4c79f5d85fdf381"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr \"'" wide fullword

	condition:
		all of them
}