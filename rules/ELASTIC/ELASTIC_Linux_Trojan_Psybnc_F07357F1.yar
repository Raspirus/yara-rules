
rule ELASTIC_Linux_Trojan_Psybnc_F07357F1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Psybnc (Linux.Trojan.Psybnc)"
		author = "Elastic Security"
		id = "f07357f1-1a92-4bd7-a43d-7a75fb90ac83"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Psybnc.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
		logic_hash = "cfe217fe108de787600d1ef06ac6738d84aedfc46e5632143692a9f83cb62df7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f0f1008fec444ce25d80f9878a04d9ebe9a76f792f4be8747292ee7b133ea05c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F7 EA 89 D0 C1 F8 02 89 CF C1 FF 1F 29 F8 8D 04 80 01 C0 29 C1 8D }

	condition:
		all of them
}