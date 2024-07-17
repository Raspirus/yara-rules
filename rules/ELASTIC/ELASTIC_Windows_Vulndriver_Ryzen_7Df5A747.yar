rule ELASTIC_Windows_Vulndriver_Ryzen_7Df5A747 : FILE
{
	meta:
		description = "Name: AMDRyzenMasterDriver.sys, Version: 1.5.0.0"
		author = "Elastic Security"
		id = "7df5a747-d924-459d-8363-9c12841ef37f"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Ryzen.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433"
		logic_hash = "192b51f0bbd2cab4c1d3da6f82fbee7129a53abaa6e8769d3681821112017824"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "1bf5d6b2739ce4fe5137cff84e7bfb9389e8d175480094fe831f8f68d84abb16"
		threat_name = "Windows.VulnDriver.Ryzen"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x05][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x04][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}