rule ELASTIC_Windows_Vulndriver_Rweverything_Aee156A5 : FILE
{
	meta:
		description = "Name: RwDrv.sys"
		author = "Elastic Security"
		id = "aee156a5-a841-4a9d-97de-1d935705b4bb"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_RWEverything.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3c5bf92c26398695f9ced7ce647a7e9f6ddcc89eea66b45aa3607196a187431b"
		logic_hash = "46b7f2ad46564c6b99f0df6146dff7c88ccbe3ad6c6d1bcbefe756606c4fe40e"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "ced97dd50a1525aeafef2192c16c1a4f29d6c70e7b3c4b196352cfc2a5c8f157"
		threat_name = "Windows.VulnDriver.RWEverything"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}