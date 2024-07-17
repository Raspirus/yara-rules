
rule ELASTIC_Windows_Trojan_Raspberryrobin_4B4D6899 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Raspberryrobin (Windows.Trojan.RaspberryRobin)"
		author = "Elastic Security"
		id = "4b4d6899-bcde-4c40-90c9-bbb621aa1ebf"
		date = "2023-12-13"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RaspberryRobin.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2f0451f38adb74cb96c857de455887b00c5038b68210294c7f52b0b5ff64cc1e"
		logic_hash = "bbafad9509b367e811e86cb8f2f64d9c1d59f82b5cd58a7af43325bb7fa9d9c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f74bd83ba1ede9b1dce070967aedc7f8df923c7393c69fcf7c4cfcf7988e0f24"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 55 89 E5 83 EC 0C 8B 45 08 3D 01 00 10 00 89 45 FC 89 4D F8 73 0F 8B 45 FC 89 45 F4 8B 4D F4 64 8B 11 89 55 F8 8B 45 F8 83 C4 0C 5D C3 }

	condition:
		all of them
}