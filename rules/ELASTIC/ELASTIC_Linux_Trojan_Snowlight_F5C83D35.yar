
rule ELASTIC_Linux_Trojan_Snowlight_F5C83D35 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Snowlight (Linux.Trojan.Snowlight)"
		author = "Elastic Security"
		id = "f5c83d35-aaa5-4356-b4e7-93dc19c0c6b1"
		date = "2024-05-16"
		modified = "2024-06-12"
		reference = "https://www.mandiant.com/resources/blog/initial-access-brokers-exploit-f5-screenconnect"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Snowlight.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7d6652d8fa3748d7f58d7e15cefee5a48126d0209cf674818f55e9a68248be01"
		logic_hash = "fef8f44e897a0f453be2f84d28886d27e261f8256c53c0425c5265b138ce5f40"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "89adbef703bec7c41350e97141d414535f5935c6c6957a0f8b25e07f405ea70e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 48 83 EC 08 48 8B 05 A5 07 20 00 48 85 C0 74 05 E8 BB 00 00 00 48 83 C4 08 C3 00 00 00 00 00 00 FF 35 9A 07 20 00 FF 25 9C 07 20 00 0F 1F 40 00 FF 25 9A 07 20 00 68 00 00 00 00 E9 E0 FF FF FF }

	condition:
		all of them
}