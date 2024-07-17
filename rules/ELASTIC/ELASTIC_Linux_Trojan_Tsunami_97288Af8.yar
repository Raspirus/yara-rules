rule ELASTIC_Linux_Trojan_Tsunami_97288Af8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "97288af8-f447-48ba-9df3-4e90f1420249"
		date = "2021-12-13"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L520-L538"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c39eb055c5f71ebfd6881ff04e876f49495c0be5560687586fc47bf5faee0c84"
		logic_hash = "c5b521cc887236a189dca419476758cee0f1513a8ad81c94b1ff42e4fe232b8e"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "a1e20b699822b47359c8585ff01da06f585b9d7187a433fe0151394b16aa8113"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 61 6E 64 65 6D 6F 20 73 68 69 72 61 6E 61 69 20 77 61 20 79 6F 2C }

	condition:
		all of them
}