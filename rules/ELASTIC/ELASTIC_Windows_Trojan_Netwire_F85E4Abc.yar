
rule ELASTIC_Windows_Trojan_Netwire_F85E4Abc : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Netwire (Windows.Trojan.Netwire)"
		author = "Elastic Security"
		id = "f85e4abc-f2d7-491b-a1ad-a59f287e5929"
		date = "2022-08-14"
		modified = "2022-09-29"
		reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Netwire.yar#L45-L64"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
		logic_hash = "af8fc8fff2e1a0b6c87ac6d24fecf2e1cefe6313ec66da13fddd1be25c1c3d92"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "66cae88c9f8b975133d2b3af94a869244d273021261815b15085c638352bf2ca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { C9 0F 44 C8 D0 EB 8A 44 24 12 0F B7 C9 75 D1 32 C0 B3 01 8B CE 88 44 }

	condition:
		all of them
}