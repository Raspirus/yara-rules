rule ELASTIC_Linux_Trojan_Mirai_76908C99 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "76908c99-e350-4dbb-9559-27cbe05f55f9"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1842-L1860"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "533a90959bfb337fd7532fb844501fd568f5f4a49998d5d479daf5dfbd01abb2"
		logic_hash = "bd8254e888b1ea93ca9aad92ea2c8ece1f2d03ae2949ca4c3743b6e339ee21e0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1741b0c2121e3f73bf7e4f505c4661c95753cbf7e0b7a1106dc4ea4d4dd73d6c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 64 24 F8 48 89 04 24 48 8B C6 48 8B 34 24 48 87 CF 48 8B 4C }

	condition:
		all of them
}