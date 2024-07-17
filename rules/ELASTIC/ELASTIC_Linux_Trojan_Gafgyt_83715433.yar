rule ELASTIC_Linux_Trojan_Gafgyt_83715433 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "83715433-3dff-4238-8cdb-c51279565e05"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3648a407224634d76e82eceec84250a7506720a7f43a6ccf5873f478408fedba"
		logic_hash = "7a7328322c2c1e128e267e92de0964e78ad9f49b7de8ec69d7f0632c69723a7d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "25ac15f4b903d9e28653dad0db399ebd20d4e9baabf5078fbc33d3cd838dd7e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 45 08 88 10 FF 45 08 8B 45 08 0F B6 00 84 C0 75 DB C9 C3 55 }

	condition:
		all of them
}