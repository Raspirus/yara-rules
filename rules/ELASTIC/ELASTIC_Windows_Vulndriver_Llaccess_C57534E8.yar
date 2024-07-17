rule ELASTIC_Windows_Vulndriver_Llaccess_C57534E8 : FILE
{
	meta:
		description = "Name: Corsair LL Access, Version: 1.0.18.0"
		author = "Elastic Security"
		id = "c57534e8-eb38-4714-9262-c489cc6204f1"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_LLAccess.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b"
		logic_hash = "8bf629fd2ce0b1f15c7aacd573659b649dcf968556232683b29d68b27d12e577"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "2eea8941c92353442f7a8986fa3abee06f83824e48bd6a3a5012f7cf76cd543e"
		threat_name = "Windows.VulnDriver.LLAccess"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 72 00 73 00 61 00 69 00 72 00 20 00 4C 00 4C 00 20 00 41 00 63 00 63 00 65 00 73 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x12][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x11][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}