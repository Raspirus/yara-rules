rule ELASTIC_Windows_Vulndriver_Gdrv_5368078B : FILE
{
	meta:
		description = "Name: gdrv.sys, Version: 5.2.3790.1830"
		author = "Elastic Security"
		id = "5368078b-5dba-42c7-a50c-ac8859d3393d"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_GDrv.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427"
		logic_hash = "f4d43ac4a4b6d879ffb5ba637b38ec75c8b57f531db644015c1a71c2cdea45d5"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "ce6e81ee34ba47466684387bdb957c3018b9c06938dbb2f7eb830609bd085f66"
		threat_name = "Windows.VulnDriver.GDrv"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x02][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\x26][\x00-\x07]|[\x00-\xff][\x00-\x06])([\x00-\xce][\x00-\x0e]|[\x00-\xff][\x00-\x0d])|([\x00-\xff][\x00-\xff])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x02][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xcd][\x00-\x0e]|[\x00-\xff][\x00-\x0d]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}