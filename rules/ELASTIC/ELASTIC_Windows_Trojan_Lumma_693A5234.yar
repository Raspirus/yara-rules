rule ELASTIC_Windows_Trojan_Lumma_693A5234 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Lumma (Windows.Trojan.Lumma)"
		author = "Elastic Security"
		id = "693a5234-de8c-4801-8146-bb4d5378abc5"
		date = "2024-06-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Lumma.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88340abcdc3cfe7574ee044aea44808446daf3bb7bf9fc60b16a2b1360c5d9c0"
		logic_hash = "2b29ac9bc73f191bdbfc92601cab923aa9f2f3380c8123ee469ced3754625dd0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9e51b8833b6fffe740f3c9f87a874dbf4d668d68307393b20cf9e4e69e899d3f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 02 0F B7 16 83 C6 02 66 85 D2 75 EF 66 C7 00 00 00 0F B7 11 }
		$a2 = { 0C 0F B7 4C 24 04 66 89 0F 83 C7 02 39 F7 73 0C 01 C3 39 EB }

	condition:
		all of them
}