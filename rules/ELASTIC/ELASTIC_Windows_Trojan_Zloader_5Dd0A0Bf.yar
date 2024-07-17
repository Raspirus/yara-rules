
rule ELASTIC_Windows_Trojan_Zloader_5Dd0A0Bf : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Zloader (Windows.Trojan.Zloader)"
		author = "Elastic Security"
		id = "5dd0a0bf-20e4-4c52-b9d9-c157e871b06b"
		date = "2022-03-03"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Zloader.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		logic_hash = "1446a4147e1b06fa66907de857011079c55a8e6bf84276eb8518d33468ba1f83"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "06545df6c556adf8a6844724e77d005c0299b544f21df2ea44bb9679964dbb9f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { B6 08 89 CA 80 C2 F7 80 FA 05 72 F2 80 F9 20 74 ED 03 5D 0C 8D }

	condition:
		all of them
}