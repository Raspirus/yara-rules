rule ELASTIC_Windows_Ransomware_Cuba_E64A16B1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Cuba (Windows.Ransomware.Cuba)"
		author = "Elastic Security"
		id = "e64a16b1-262c-4835-bd95-4dde89dd75f4"
		date = "2021-08-04"
		modified = "2021-10-04"
		reference = "https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Cuba.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "33352a38454cfc247bc7465bf177f5f97d7fd0bd220103d4422c8ec45b4d3d0e"
		logic_hash = "915425ad49f1b9ebde114f92155d5969ec707304403f46d891d014b399165a4d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "840f2ebe2664db9a0918acf7d408ca8060ee0d3c330ad08b36e5be7f7e2cf069"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 45 EC 8B F9 8B 45 14 89 45 F0 8D 45 E4 50 8D 45 F8 66 0F 13 }
		$HeaderCheck = { 8B 06 81 38 46 49 44 45 75 ?? 81 78 04 4C 2E 43 41 74 }

	condition:
		any of them
}