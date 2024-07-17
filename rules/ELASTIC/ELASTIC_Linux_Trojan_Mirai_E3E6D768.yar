
rule ELASTIC_Linux_Trojan_Mirai_E3E6D768 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "e3e6d768-6510-4eb2-a5ec-8cb8eead13f2"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L696-L714"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b505cb26d3ead5a0ef82d2c87a9b352cc0268ef0571f5e28defca7131065545e"
		logic_hash = "b848c7200f405d77553d661a6c49fb958df225875957ead35b35091995f307d1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ce11f9c038c31440bcdf7f9d194d1a82be5d283b875cc6170a140c398747ff8c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 7E 14 48 89 DF 48 63 C8 4C 89 E6 FC F3 A4 41 01 C5 48 89 FB }

	condition:
		all of them
}