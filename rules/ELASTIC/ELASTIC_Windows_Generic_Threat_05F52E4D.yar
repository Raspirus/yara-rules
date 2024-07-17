
rule ELASTIC_Windows_Generic_Threat_05F52E4D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "05f52e4d-d131-491a-a037-069b450e3b3e"
		date = "2024-03-04"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2983-L3001"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e578b795f8ed77c1057d8e6b827f7426fd4881f02949bfc83bcad11fa7eb2403"
		logic_hash = "79898b59b6d3564aad85d823a1450600faff5b1d2dbfbe0cee4cc59971e4f542"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f3d5f6dc1f9b51ce1700605c8a018000124d66a260771de0da1a321dc97872dd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 28 00 00 06 73 45 00 00 0A 73 46 00 00 0A 6F 47 00 00 0A 14 FE 06 29 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0B 14 FE 06 2A 00 00 06 73 45 00 00 0A 73 46 00 00 0A 0C 07 6F 47 00 00 0A 08 6F 47 }

	condition:
		all of them
}