rule ELASTIC_Windows_Trojan_Nighthawk_2A2E3B9D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Nighthawk (Windows.Trojan.Nighthawk)"
		author = "Elastic Security"
		id = "2a2e3b9d-e85f-43b6-9754-1aa7c9f6f978"
		date = "2022-11-24"
		modified = "2023-06-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Nighthawk.yar#L28-L47"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf"
		logic_hash = "c42605ebba900fafb4ec2d34d93bb7adb69e731ce151b82a95889dd0d738da00"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "40912e8d6bd09754046598b1311080e0ec6e040cb1b9ca93003c6314725d4d45"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$payload_bytes1 = { 66 C1 E0 05 66 33 D0 66 C1 E2 0A 66 0B D1 0F B7 D2 8B CA 0F B7 C2 C1 E9 02 33 CA 66 D1 E8 D1 E9 33 CA C1 E9 02 33 CA C1 E2 0F 83 E1 01 }
		$payload_bytes2 = { 48 8B D9 44 8B C2 41 C1 E0 0F 8B C2 F7 D0 48 8B F2 44 03 C0 41 8B C0 C1 E8 0C 41 33 C0 8D 04 80 8B C8 C1 E9 04 33 C8 44 69 C1 09 08 00 00 41 8B C0 C1 E8 10 44 33 C0 B8 85 1C A7 AA }

	condition:
		any of them
}