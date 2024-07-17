
rule ELASTIC_Windows_Trojan_Tofsee_26124Fe4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Tofsee (Windows.Trojan.Tofsee)"
		author = "Elastic Security"
		id = "26124fe4-f2a1-4fc9-8155-585b581476de"
		date = "2022-03-31"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Tofsee.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e658fe6d3bd685f41eb0527432099ee01075bfdb523ef5aa3e5ebd42221c8494"
		logic_hash = "e765953dec7c7b2a1fbebf92c2fff46453c8258722ad5ca92ba4c7526a8b0c66"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dc7ada5c6341e98bc41182a5698527b1649c4e80924ba0405f1b94356f63ff31"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 8B EC 8B 45 ?? 57 8B 7D ?? B1 01 85 FF 74 ?? 56 8B 75 ?? 2B F0 8A 14 06 32 55 ?? 88 10 8A D1 02 55 ?? F6 D9 00 55 ?? 40 4F 75 ?? 5E 8B 45 ?? 5F 5D C3 }
		$b = { 8B 44 24 ?? 53 8A 18 84 DB 74 ?? 8B D0 2B 54 24 ?? 8B 4C 24 ?? 84 DB 74 ?? 8A 19 84 DB 74 ?? 38 1C 0A 75 ?? 41 80 3C 0A 00 75 ?? 80 39 00 74 ?? 40 8A 18 42 84 DB 75 ?? 33 C0 5B C3 }

	condition:
		any of them
}