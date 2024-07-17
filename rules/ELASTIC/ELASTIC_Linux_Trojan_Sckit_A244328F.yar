rule ELASTIC_Linux_Trojan_Sckit_A244328F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Sckit (Linux.Trojan.Sckit)"
		author = "Elastic Security"
		id = "a244328f-1e12-4ae6-b583-ecf14a4b9d82"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Sckit.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "685da66303a007322d235b7808190c3ea78a828679277e8e03e6d8d511df0a30"
		logic_hash = "8001c9fcf9f8b70c3e27554156b0b26ddcd6cab36bf97cf3b89a4c43c9ad883c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "eca152c730ecabbc9fe49173273199cb37b343d038084965ad880ddba3173f50"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 34 D0 04 08 BB 24 C3 04 08 CD 80 C7 05 A0 EE 04 }

	condition:
		all of them
}