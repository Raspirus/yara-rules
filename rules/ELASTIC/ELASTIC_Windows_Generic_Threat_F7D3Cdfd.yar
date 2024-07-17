rule ELASTIC_Windows_Generic_Threat_F7D3Cdfd : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "f7d3cdfd-72eb-4298-b3ff-432f5c4347c9"
		date = "2024-01-07"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L733-L751"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f9df83d0b0e06884cdb4a02cd2091ee1fadeabb2ea16ca34cbfef4129ede251f"
		logic_hash = "23e1008f222eb94a4bd34372834924377e813dc76efa8544b0dcbe7d3e3addde"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "db703a2ddcec989a81b99a67e61f4be34a2b0e55285c2bdec91cd2f7fc7e52f3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 51 56 57 E8 A3 D0 FF FF 83 78 68 00 74 21 FF 75 24 FF 75 20 FF 75 18 FF 75 14 FF 75 10 FF 75 0C FF 75 08 E8 E5 8C FF FF 83 C4 1C 85 C0 75 73 8B 7D 1C 8D 45 F8 50 8D 45 FC 50 57 FF }

	condition:
		all of them
}