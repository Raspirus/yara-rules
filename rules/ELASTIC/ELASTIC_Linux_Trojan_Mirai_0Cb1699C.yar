
rule ELASTIC_Linux_Trojan_Mirai_0Cb1699C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "0cb1699c-9a08-4885-aa7f-0f1ee2543cac"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L80-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		logic_hash = "97307f583240290de2bfc663b99f8dcdedace92885bd3e0c0340709b94c0bc2a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6e44c68bba8c9fb53ac85080b9ad765579f027cabfea5055a0bb3a85b8671089"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DB 8B 4C 24 0C 8B 54 24 08 83 F9 01 76 10 0F B7 02 83 E9 02 83 }

	condition:
		all of them
}