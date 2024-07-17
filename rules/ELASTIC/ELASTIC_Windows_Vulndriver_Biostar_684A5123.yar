
rule ELASTIC_Windows_Vulndriver_Biostar_684A5123 : FILE
{
	meta:
		description = "Name: BS_RCIO64.sys, Version: 10.0.0.1"
		author = "Elastic Security"
		id = "684a5123-cd84-4133-9530-30bfefd5ad1b"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Biostar.yar#L45-L65"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e"
		logic_hash = "7c0c7e14f9b5085a87e5dbe27feb8e49bdb4d2fdcfbcbc643999d7969d118240"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "c92b058bbc8a708431bdbe8fc2e793c0a424aa79b25892c83153ffd32e1a89d3"
		threat_name = "Windows.VulnDriver.Biostar"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 52 00 43 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}