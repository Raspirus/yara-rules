rule ELASTIC_Windows_Vulndriver_Rtkio_D595781E : FILE
{
	meta:
		description = "Name: rtkio64.sys"
		author = "Elastic Security"
		id = "d595781e-67c1-47bf-a7ea-bb4a9ba33879"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Rtkio.yar#L22-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4ed2d2c1b00e87b926fb58b4ea43d2db35e5912975f4400aa7bd9f8c239d08b7"
		logic_hash = "289eb17025d989cc74e109b1c03378e9760817a84f1a759153ff6ff6b6401e6d"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "efe0871703d5c146764c4a7ac9c80ae4e635dc6dd0e718e6ddc4c39b18ca9fdd"
		threat_name = "Windows.VulnDriver.Rtkio"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}