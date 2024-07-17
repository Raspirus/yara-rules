
rule ELASTIC_Windows_Vulndriver_Sandra_612A7A16 : FILE
{
	meta:
		description = "Name: sandra.sys, Version: 10.12.0.0"
		author = "Elastic Security"
		id = "612a7a16-b616-4a70-9994-cb5aebfa0ca9"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Sandra.yar#L23-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8fda0e1775d903b73836d4103f6e8b0e2f052026b3acdb07bd345b9ddb3c873a"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "ead3bd8256fbb5d26c4a177298a5cdd14e5eeb73d9336999c0a68ece9efa2d55"
		threat_name = "Windows.VulnDriver.Sandra"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 61 00 6E 00 64 00 72 00 61 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0c][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}