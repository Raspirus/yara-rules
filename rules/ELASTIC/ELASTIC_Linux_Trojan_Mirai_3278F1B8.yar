
rule ELASTIC_Linux_Trojan_Mirai_3278F1B8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "3278f1b8-f208-42c8-a851-d22413f74dea"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1462-L1480"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		logic_hash = "4d709e8e2062099ac06b241408e52bcb86bbf8163faaffbcff68a05f864e1b3f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7e9fc284c9c920ac2752911d6aacbc3c2bf1b053aa35c22d83bab0089290778d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D2 0F B6 C3 C1 E0 10 0F B6 C9 C1 E2 18 09 C2 0F B6 44 24 40 C1 }

	condition:
		all of them
}