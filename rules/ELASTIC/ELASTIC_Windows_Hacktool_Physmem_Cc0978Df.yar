
rule ELASTIC_Windows_Hacktool_Physmem_Cc0978Df : FILE
{
	meta:
		description = "Name: physmem.sys"
		author = "Elastic Security"
		id = "cc0978df-153e-4421-8be8-37a0824133e2"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_PhysMem.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c299063e3eae8ddc15839767e83b9808fd43418dc5a1af7e4f44b97ba53fbd3d"
		logic_hash = "e2fabf5889dbdc98dc6942be4fb0de4351d64a06bab945993b2a2c4afe89984e"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "b94d5530dc3db4101b6ef06dc2421a10785f47bcb26d54f309a250a68699fa83"
		threat_name = "Windows.Hacktool.PhysMem"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 68 00 79 00 73 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}