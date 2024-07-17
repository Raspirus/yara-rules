rule ELASTIC_Linux_Trojan_Mirai_612B407C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "612b407c-fceb-4a19-8905-2f5b822f62cc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1541-L1559"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7833bc89778461a9f46cc47a78c67dda48b498ee40b09a80a21e67cb70c6add1"
		logic_hash = "6514725a32f7c28be7de5ff6fe1363df7c50e2cd6c8c79824ec4cbeadda2ca31"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c48c26b1052ef832d4d6a106db186bf20c503bdf38392a1661eb2d3c3ec010cd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 11 B2 73 45 2B 7A 57 E2 F9 77 A2 23 EC 7C 0C 29 FE 3F B2 DE 28 6C }

	condition:
		all of them
}