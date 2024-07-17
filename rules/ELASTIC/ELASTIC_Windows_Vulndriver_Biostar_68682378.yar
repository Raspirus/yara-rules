rule ELASTIC_Windows_Vulndriver_Biostar_68682378 : FILE
{
	meta:
		description = "Name: BS_I2cIo.sys, Version: 1.1.0.0"
		author = "Elastic Security"
		id = "68682378-9b49-4bec-b24c-aba8221a62fe"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Biostar.yar#L23-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a"
		logic_hash = "8510de6fc33bde153f3bd4d1bb8b0d98ce69aae479d242c6043ac8c712dbb888"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "df974c8b5bb60b1b6e95d1c70c968dfca1f1e351f50eed29d215da673d45af19"
		threat_name = "Windows.VulnDriver.Biostar"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 49 00 32 00 63 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}