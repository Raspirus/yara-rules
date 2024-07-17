
rule ELASTIC_Windows_Vulndriver_Xtier_F4760D4A : FILE
{
	meta:
		description = "Name: NICM.SYS, Version: 3.1.12.0"
		author = "Elastic Security"
		id = "f4760d4a-42da-4bb8-87ff-3b2e709c6a95"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_XTier.yar#L45-L65"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0e14a4401011a9f4e444028ac5b1595da34bbbf9af04a00670f15ff839734003"
		logic_hash = "dc83771e08b8530bf138782ba8c7724e7ecff40c973407a7f654346302a284d5"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "95f3b1f788edb8a6cd121dc44fd1426ff1b29cf3231c6f3f4ec434d288cd8deb"
		threat_name = "Windows.VulnDriver.XTier"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 49 00 43 00 4D 00 2E 00 53 00 59 00 53 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}