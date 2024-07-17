
rule ELASTIC_Windows_Trojan_Bruteratel_5B12Cbab : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bruteratel (Windows.Trojan.BruteRatel)"
		author = "Elastic Security"
		id = "5b12cbab-c64c-4895-a186-b940bf4a8620"
		date = "2024-02-21"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BruteRatel.yar#L132-L150"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8165798fec8294523f25aedfc6699faad0c5d75f60bc7cefcbb2fa13dbc656e3"
		logic_hash = "b86296dafaef1dfa0a41704cafa351694abb0e453e104dfe06836ed599338f38"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "33e4c8fa032f33bec4719707d3ddcfa5103b747d9be70fa41848fdafd254c0ac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 81 EC 00 01 00 00 31 C0 41 89 D3 48 89 E3 88 04 18 48 FF C0 48 3D 00 01 00 00 75 F2 45 31 D2 31 FF 44 89 D0 42 8A 34 13 99 41 F7 FB 48 63 D2 8A 04 11 01 F0 01 F8 0F B6 F8 0F B6 C0 8A 14 04 }

	condition:
		all of them
}