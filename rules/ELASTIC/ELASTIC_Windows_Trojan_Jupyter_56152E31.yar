
rule ELASTIC_Windows_Trojan_Jupyter_56152E31 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Jupyter (Windows.Trojan.Jupyter)"
		author = "Elastic Security"
		id = "56152e31-77c6-49fa-bbc5-c3630f11e633"
		date = "2021-07-22"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Jupyter.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ce486097ad2491aba8b1c120f6d0aa23eaf59cf698b57d2113faab696d03c601"
		logic_hash = "7b32e9caca744f4f6b48aefa5fda111e6b7ac81a62dd1fb8873d2c800ac3c42b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9cccc2e3d4cfe9ff090d02b143fa837f4da0c229426435b4e097f902e8c5fb01"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "%appdata%\\solarmarker.dat" ascii fullword
		$a2 = "\\AppData\\Roaming\\solarmarker.dat" wide fullword
		$b1 = "steal_passwords" ascii fullword
		$b2 = "jupyter" ascii fullword

	condition:
		1 of ($a*) or 2 of ($b*)
}