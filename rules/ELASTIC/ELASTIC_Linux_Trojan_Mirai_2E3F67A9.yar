rule ELASTIC_Linux_Trojan_Mirai_2E3F67A9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "2e3f67a9-6fd5-4457-a626-3a9015bdb401"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1125-L1143"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		logic_hash = "8c83c5d32c58041444f33264f692a7580c76324d2cbad736fdd737bdfcd63595"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6a06815f3d2e5f1a7a67f4264953dbb2e9d14e5f3486b178da845eab5b922d4f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 53 83 EC 04 0F B6 74 24 14 8B 5C 24 18 8B 7C 24 20 0F B6 44 }

	condition:
		all of them
}