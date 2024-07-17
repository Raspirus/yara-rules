
rule ELASTIC_Windows_Vulndriver_Atillk_18316Dd9 : FILE
{
	meta:
		description = "Name: atillk64.sys, Version: 5.11.9.0"
		author = "Elastic Security"
		id = "18316dd9-0a58-4e06-bebd-13f3de45c054"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Atillk.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ad40e6d0f77c0e579fb87c5106bf6de3d1a9f30ee2fbf8c9c011f377fa05f173"
		logic_hash = "02d218d0a0ea447e4ad0b03bff50c307ca5f36b8ed268787cd73c88a05aa4214"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "74d618e50edf662aae13e7577a02cfc54c5a15045b34acdb2f5714ce8c65a487"
		threat_name = "Windows.VulnDriver.Atillk"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 74 00 69 00 6C 00 6C 00 6B 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0b][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x09][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0a][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x08][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}