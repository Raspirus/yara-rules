rule ELASTIC_Windows_Ransomware_Lockbit_A1C60939 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Lockbit (Windows.Ransomware.Lockbit)"
		author = "Elastic Security"
		id = "a1c60939-e257-420d-87ed-f31f30f2fc2a"
		date = "2021-08-06"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Lockbit.yar#L23-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0d6524b9a1d709ecd9f19f75fa78d94096e039b3d4592d13e8dbddf99867182d"
		logic_hash = "6e6d88251e93f69788ad22fc915133f3ba0267984d6a5004d5ca44dcd9f5f052"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a41fb21e82ee893468393428d655b03ce251d23f34acb54bbf01ae0eb86817bf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 3C 8B 4C 18 78 8D 04 19 89 45 F8 3B C3 74 70 33 C9 89 4D F4 39 }

	condition:
		all of them
}