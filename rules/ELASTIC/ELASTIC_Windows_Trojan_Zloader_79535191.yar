
rule ELASTIC_Windows_Trojan_Zloader_79535191 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Zloader (Windows.Trojan.Zloader)"
		author = "Elastic Security"
		id = "79535191-59df-4c78-9f62-b8614ef992d3"
		date = "2022-03-03"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Zloader.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		logic_hash = "c398a8ca46c6fe3e59481a092867be77a94809b1568cea918aa6450374063857"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ee3c4cf0d694119acfdc945a964e4fc0f51355eabca900ffbcc21aec0b3e1e3c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 28 4B 74 26 8B 46 FC 85 C0 74 F3 8B 4E F4 8B 16 39 C8 0F 47 C1 8B }

	condition:
		all of them
}