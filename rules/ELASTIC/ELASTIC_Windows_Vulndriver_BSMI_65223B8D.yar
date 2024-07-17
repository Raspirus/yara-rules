rule ELASTIC_Windows_Vulndriver_BSMI_65223B8D : FILE
{
	meta:
		description = "Name: BSMI.sys, Version: 1.0.0.3"
		author = "Elastic Security"
		id = "65223b8d-451a-4ae6-90cc-17d1482cc834"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_BSMI.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347"
		logic_hash = "c4fa65bbd9d374092137b65209f29744caeb8b04fbd364b1acc67b73c45604e8"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "9ad213d919719d0fb0a99dcb9863720adec173e9801663e1cf5b99881435914a"
		threat_name = "Windows.VulnDriver.BSMI"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 4D 00 49 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}