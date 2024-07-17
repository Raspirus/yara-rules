
rule ELASTIC_Linux_Trojan_Mirai_1Cb033F3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "1cb033f3-68c1-4fe5-9cd1-b5d066c1d86e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L41-L58"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "ebaf45ce58124aa91b07ebb48779e6da73baa0b80b13e663c13d8fb2bb47ad0d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "49201ab37ff0b5cdfa9b0b34b6faa170bd25f04df51c24b0b558b7534fecc358"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C3 EB 06 8A 46 FF 88 47 FF FF CA 48 FF C7 48 FF C6 83 FA FF }

	condition:
		all of them
}