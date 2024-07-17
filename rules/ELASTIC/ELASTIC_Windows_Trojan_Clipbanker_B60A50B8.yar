
rule ELASTIC_Windows_Trojan_Clipbanker_B60A50B8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Clipbanker (Windows.Trojan.Clipbanker)"
		author = "Elastic Security"
		id = "b60a50b8-91a4-49a7-bd05-fa4cc1dee1ac"
		date = "2022-02-28"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Clipbanker.yar#L25-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
		logic_hash = "fe585ab7efbc3b500ea23d1c164bc79ded658001e53fc71721e435ed7579182a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "097bb88d8482a4915c19affc82750c7ee225b89f2611ea654cfc3c044aae0738"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 40 66 0F F8 C1 0F 11 40 A0 0F 10 84 15 08 FF FF FF 83 C2 40 }

	condition:
		all of them
}