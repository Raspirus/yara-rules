rule ELASTIC_Linux_Generic_Threat_887671E9 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "887671e9-1e93-42d9-afb8-a96d1a87c572"
		date = "2024-02-01"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L490-L508"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "701c7c75ed6a7aaf59f5a1f04192a1f7d49d73c1bd36453aed703ad5560606dc"
		logic_hash = "eefe9391a9ce716dbe16f11b8ccea89d032fdad42fcabd84ffe584409c550847"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "55cbfbd761e2000492059909199d16faf6839d3d893e29987b73087942c9de78"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 55 89 E5 57 56 53 83 E4 F0 83 EC 40 8B 45 0C E8 DC 04 00 00 81 C3 AC F7 0B 00 89 44 24 04 8B 45 08 89 04 24 E8 A7 67 00 00 85 C0 0F 88 40 04 00 00 C7 04 24 00 00 00 00 E8 03 F5 FF FF 8B 93 34 }

	condition:
		all of them
}