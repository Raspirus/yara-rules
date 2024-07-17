
rule ELASTIC_Linux_Cryptominer_Xmrminer_2B250178 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrminer (Linux.Cryptominer.Xmrminer)"
		author = "Elastic Security"
		id = "2b250178-3f9a-4aeb-819a-970b5ef9c98a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrminer.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "636605cf63d3e335fe9481d4d110c43572e9ab365edfa2b6d16d96b52d6283ef"
		logic_hash = "067705c52de710372b4a2a3b77427106068ad2d9a8e56602e315d09e7b8b6206"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e297a790a78d32b973d6a028a09c96186c3971279b5c5eea4ff6409f12308e67"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 03 7E 11 8B 44 24 38 89 EF 31 D2 89 06 8B 44 24 3C 89 46 04 F7 C7 02 00 }

	condition:
		all of them
}