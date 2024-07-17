rule ELASTIC_Windows_Ransomware_Ragnarok_7E802F95 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RAGNAROK ransomware"
		author = "Elastic Security"
		id = "7e802f95-964e-4dd9-a5d1-13a6cd73d750"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ragnarok.yar#L22-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8f293cdbdc3c395e18c304dfa43d0dcdb52b18bde5b5d084190ceec70aea6cbd"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "c62b3706a2024751f1346d0153381ac28057995cf95228e43affc3d1e4ad0fad"
		threat_name = "Windows.Ransomware.Ragnarok"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d1 = { 68 04 94 42 00 FF 35 A0 77 43 00 }
		$d2 = { 68 90 94 42 00 FF 35 A0 77 43 00 E8 8F D6 00 00 8B 40 10 50 }

	condition:
		1 of ($d*)
}