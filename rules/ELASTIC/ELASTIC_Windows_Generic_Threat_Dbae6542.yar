
rule ELASTIC_Windows_Generic_Threat_Dbae6542 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "dbae6542-b343-4320-884c-c0ce97a431f1"
		date = "2024-01-10"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L874-L892"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c73f533f96ed894b9ff717da195083a594673e218ee9a269e360353b9c9a0283"
		logic_hash = "673c6b4e6aaa127d45b21d0283437000fbc507a84ecd7a326448869d63759aee"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "880aafd423494eccab31342bdfec392fdf4a7b4d98614a0c3b5302d62bcf5ba8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0F 00 00 04 2D 0A 28 27 00 00 06 28 19 00 00 06 7E 15 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A EE 16 80 0F 00 00 04 14 }

	condition:
		all of them
}