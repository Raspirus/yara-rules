
rule ELASTIC_Linux_Trojan_Mirai_Da4Aa3B3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "da4aa3b3-521d-4fde-b1be-c381d28c701c"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L358-L376"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dbc246032d432318f23a4c1e5b6fcd787df29da3bf418613f588f758dcd80617"
		logic_hash = "84ddc505d2e2be955b88a0fe3b78d435f73c0a315b513e105933e84be78ba2ad"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8b004abc37f47de6e4ed35284c23db0f6617eec037a71ce92c10aa8efc3bdca5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 D0 C1 E0 03 89 C2 8B 45 A0 01 D0 0F B6 40 14 3C 1F 77 65 8B }

	condition:
		all of them
}