
rule ELASTIC_Linux_Trojan_Godropper_Bae099Bd : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Godropper (Linux.Trojan.Godropper)"
		author = "Elastic Security"
		id = "bae099bd-c19a-4893-96e8-63132dabce39"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Godropper.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "704643f3fd11cda1d52260285bf2a03bccafe59cfba4466427646c1baf93881e"
		logic_hash = "ef6274928f7cfc0312122ac3e4153fb0a78dc7d5fb2d68db6cbe4974f5497210"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5a7b0906ebc47130aefa868643e1e0a40508fe7a25bc55e5c41ff284ca2751e5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF FF FF FF 88 DB A2 31 03 A3 5A 5C 9A 19 0E DB }

	condition:
		all of them
}