rule ELASTIC_Windows_Generic_Threat_1417511B : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "1417511b-2b31-47a8-8465-b6a174174863"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1566-L1584"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2fc9bd91753ff3334ef7f9861dc1ae79cf5915d79fa50f7104cbb3262b7037da"
		logic_hash = "e6b53082fa447ac3cf56784771aca742696922e6f740a24d014e04250dc5020c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4be19360fccf794ca2e53c4f47cd1becf476becf9eafeab430bdb3c64581613c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 20 8B 45 08 89 45 F4 8B 4D F4 8B 55 08 03 51 3C 89 55 F0 B8 08 00 00 00 6B C8 00 8B 55 F0 8B 45 08 03 44 0A 78 89 45 F8 8B 4D F8 8B 55 08 03 51 20 89 55 EC 8B 45 F8 8B 4D 08 03 }

	condition:
		all of them
}