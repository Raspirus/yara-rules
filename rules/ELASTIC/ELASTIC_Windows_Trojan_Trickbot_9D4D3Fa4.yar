
rule ELASTIC_Windows_Trojan_Trickbot_9D4D3Fa4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Trickbot (Windows.Trojan.Trickbot)"
		author = "Elastic Security"
		id = "9d4d3fa4-4e37-40d7-8399-a49130b7ef49"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L212-L229"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "7c3c9917a95248fd990b6947a0304ded473bf1bcceec8f4498a7955e879d348b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b06c3c7ba1f5823ce381971ed29554e5ddbe327b197de312738165ee8bf6e194"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 89 44 24 18 33 C9 89 44 24 1C 8D 54 24 38 89 44 24 20 33 F6 89 44 }

	condition:
		all of them
}