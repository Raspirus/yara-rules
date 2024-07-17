
rule ELASTIC_Windows_Trojan_Merlin_E8Ecb3Be : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Merlin (Windows.Trojan.Merlin)"
		author = "Elastic Security"
		id = "e8ecb3be-edba-4617-b4df-9d5b6275d310"
		date = "2022-01-05"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Merlin.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "768c120e63d3960a0842dcc538749955ab7caabaeaf3682f6d1e30666aac65a8"
		logic_hash = "293158c981463544abd0c38694bfc8635ad1a679bbae115521b65879f145cea6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "54e03337930d74568a91e797cfda3b7bfbce3aad29be2543ed58c51728d8e185"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { AF F0 4C 01 F1 4C 8B B4 24 A8 00 00 00 4D 0F AF F4 4C 01 F1 4C 8B B4 24 B0 00 }

	condition:
		all of them
}