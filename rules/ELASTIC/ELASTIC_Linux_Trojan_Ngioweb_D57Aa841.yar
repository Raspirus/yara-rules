rule ELASTIC_Linux_Trojan_Ngioweb_D57Aa841 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "d57aa841-8eb5-4765-9434-233ab119015f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "555d60bd863caff231700c5f606d0034d5aa8362862d1fd0c816615d59f582f7"
		logic_hash = "b0db72ad81d27f5b2ac2d2bb903ff10849c304d40619fd95a39e7d48c64c45ba"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "83a4eb7c8ac42097d3483bcf918823105b4ea4291a566b4184eacc2a0f3aa3a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 0C 48 89 4C 24 10 4C 89 44 24 18 66 83 F8 02 74 10 BB 10 00 }

	condition:
		all of them
}