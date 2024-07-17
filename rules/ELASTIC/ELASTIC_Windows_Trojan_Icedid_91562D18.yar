
rule ELASTIC_Windows_Trojan_Icedid_91562D18 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "91562d18-28a1-4349-9e4b-92ad165510c9"
		date = "2022-04-06"
		modified = "2022-06-09"
		reference = "https://www.elastic.co/security-labs/thawing-the-permafrost-of-icedid-summary"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L144-L163"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		logic_hash = "81c87d0d6726bc2dde42fe93c77af53cdd29bb6437fe3d47d1b4550140722c88"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "024bbd15da6bc759e321779881b466b500f6364a1d67bbfdc950aedccbfbc022"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 44 8B 4C 19 2C 4C 03 D6 74 1C 4D 85 C0 74 17 4D 85 C9 74 12 41 }

	condition:
		all of them
}