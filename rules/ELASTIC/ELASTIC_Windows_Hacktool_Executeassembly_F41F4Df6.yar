rule ELASTIC_Windows_Hacktool_Executeassembly_F41F4Df6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Executeassembly (Windows.Hacktool.ExecuteAssembly)"
		author = "Elastic Security"
		id = "f41f4df6-03de-4a03-9dfa-4f9d0f51c2de"
		date = "2023-03-28"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_ExecuteAssembly.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a468ba2ba77aafa2a572c8947d414e74604a7c1c6e68a0b87fbfce4f8854dd61"
		logic_hash = "ab72dec636a96338e16fd57f2db4bb52e38fe61315b42c2ffe9c4566fc0326d3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4875f516551517ec9423f04a9636b65fc717b9e2c9c40379b027ab126e593d23"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$bytes0 = { 33 D8 8B C3 C1 E8 05 03 D8 8B C3 C1 E0 04 33 D8 8B C3 C1 E8 11 03 D8 8B C3 C1 E0 19 33 D8 8B C3 C1 E8 06 03 C3 }
		$bytes1 = { 81 F9 8E 4E 0E EC 74 10 81 F9 AA FC 0D 7C 74 08 81 F9 54 CA AF 91 75 43 }

	condition:
		all of them
}