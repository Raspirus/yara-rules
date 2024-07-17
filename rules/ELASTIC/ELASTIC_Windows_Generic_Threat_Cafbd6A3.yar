rule ELASTIC_Windows_Generic_Threat_Cafbd6A3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "cafbd6a3-c367-467d-b305-fb262e4d6d07"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2314-L2333"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "97081a51aa016d0e6c9ecadc09ff858bf43364265a006db9d7cc133f8429bc46"
		logic_hash = "28813fc8a49b6ec3fe7675409fde923f0f30851429a526c142e0a228b4e0efa6"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "d3237c30fb6eef10b89dc9138572f781cc7d9dad1524e2e27eee82c50f863fbb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 6C 6B 73 6A 66 68 67 6C 6B 6A 66 73 64 67 31 33 31 }
		$a2 = { 72 65 67 20 44 65 6C 65 74 65 20 22 48 4B 4C 4D 5C 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 20 4E 54 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 52 75 6E 4F 6E 63 65 22 20 2F 66 20 3E 20 6E 75 6C }

	condition:
		all of them
}