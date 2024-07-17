
rule ELASTIC_Windows_Vulndriver_Microstar_D72B85B2 : FILE
{
	meta:
		description = "Name: NTIOLib.sys, Version: 1.0.0.0"
		author = "Elastic Security"
		id = "d72b85b2-b51e-4061-909c-cce531513367"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_MicroStar.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3ed15a390d8dfbd8a8fb99e8367e19bfd1cced0e629dfe43ccdb46c863394b59"
		logic_hash = "04e9c1f318acae5544cdc826938383bf8f6c6b838cb5828a7097383ac564f404"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "a531bc0b1a94b532694c9ae421db258007d835e03cf2580a1b5a10e5686063e5"
		threat_name = "Windows.VulnDriver.MicroStar"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 54 00 49 00 4F 00 4C 00 69 00 62 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}