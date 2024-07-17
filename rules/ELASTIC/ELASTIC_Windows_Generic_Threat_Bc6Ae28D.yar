
rule ELASTIC_Windows_Generic_Threat_Bc6Ae28D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "bc6ae28d-050b-43d9-ba57-82fb37a2bc91"
		date = "2023-12-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ce00873eb423c0259c18157a07bf7fd9b07333e528a5b9d48be79194310c9d97"
		logic_hash = "0ca5ec945858a5238eac048520dea4597f706ad2c96be322d341c84c4ddbce33"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "40a45e5b109a9b48cecd95899ff6350af5d28deb1c6f3aa4f0363ed3abf62bf7"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C 24 E8 DB FC FF FF 85 C0 74 05 8B 45 F0 C9 C3 83 C8 FF C9 C3 55 8B EC 83 EC 24 83 79 08 00 75 19 DD 01 8D 45 DC 50 51 51 DD 1C }

	condition:
		all of them
}