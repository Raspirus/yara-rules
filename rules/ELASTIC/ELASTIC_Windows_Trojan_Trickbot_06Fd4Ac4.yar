rule ELASTIC_Windows_Trojan_Trickbot_06Fd4Ac4 : FILE MEMORY
{
	meta:
		description = "Identifies Trickbot unpacker"
		author = "Elastic Security"
		id = "06fd4ac4-1155-4068-ae63-4d83db2bd942"
		date = "2021-03-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "bde387f1e22d1399fb99f6d41732a37635d8e90f29626f2995914a073a7cac89"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ece49004ed1d27ef92b3b1ec040d06e90687d4ac5a89451e2ae487d92cb24ddd"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 5F 33 C0 68 ?? ?? 00 00 59 50 E2 FD 8B C7 57 8B EC 05 ?? ?? ?? 00 89 45 04 }

	condition:
		all of them
}