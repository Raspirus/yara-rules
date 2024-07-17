rule ELASTIC_Windows_Ransomware_Generic_99F5A632 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Generic (Windows.Ransomware.Generic)"
		author = "Elastic Security"
		id = "99f5a632-8562-4321-b707-c5f583b14511"
		date = "2022-02-24"
		modified = "2022-02-24"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Generic.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"
		logic_hash = "2284cfc91d17816f1733e8fe319af52bc66af467364d27f84e213082c216ae8b"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "84ab8d177e50bce1a3eceb99befcf05c7a73ebde2f7ea4010617bf4908257fdb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "stephanie.jones2024@protonmail.com"
		$a2 = "_/C_/projects/403forBiden/wHiteHousE.init" ascii fullword
		$a3 = "All your files, documents, photoes, videos, databases etc. have been successfully encrypted" ascii fullword
		$a4 = "<p>Do not try to decrypt then by yourself - it's impossible" ascii fullword

	condition:
		all of them
}