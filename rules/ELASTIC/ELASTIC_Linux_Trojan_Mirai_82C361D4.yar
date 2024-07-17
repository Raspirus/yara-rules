
rule ELASTIC_Linux_Trojan_Mirai_82C361D4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "82c361d4-2adf-48f2-a9be-677676d7451f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1204-L1222"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f8dbcf0fc52f0c717c8680cb5171a8c6c395f14fd40a2af75efc9ba5684a5b49"
		logic_hash = "766a964d7d35525fbc88adcf86fb69d11f9c63c0d28ceefb3ae79797a7161193"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a8a4252c6f7006181bdb328d496e0e29522f87e55229147bc6cf4d496f5828fb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 23 CB 67 4C 94 11 6E 75 EC A6 76 98 23 CC 80 CF AE 3E A6 0C }

	condition:
		all of them
}