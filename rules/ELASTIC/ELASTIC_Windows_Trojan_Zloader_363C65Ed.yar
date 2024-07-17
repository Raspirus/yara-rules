rule ELASTIC_Windows_Trojan_Zloader_363C65Ed : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Zloader (Windows.Trojan.Zloader)"
		author = "Elastic Security"
		id = "363c65ed-e394-4a40-9c2a-a6f6fd284ed3"
		date = "2022-03-03"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Zloader.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		logic_hash = "d3c530f9929db709067a9e1cc59b9cda9dcd8e19352c79ddaf7af6c91b242afd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "33ae4cee122269f4342a3fd829236cbd303d8821b548ab93bbebc9dee3eb67f2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 04 8D 4D E4 8D 55 E8 6A 00 6A 00 51 6A 00 6A 00 50 52 57 53 }

	condition:
		all of them
}