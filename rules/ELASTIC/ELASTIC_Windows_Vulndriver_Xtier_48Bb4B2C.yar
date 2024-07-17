rule ELASTIC_Windows_Vulndriver_Xtier_48Bb4B2C : FILE
{
	meta:
		description = "Name: nscm.sys, Version: 3.1.12.0"
		author = "Elastic Security"
		id = "48bb4b2c-da6c-4e2a-bbbe-75c7a892bdc6"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_XTier.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0f726d8ce21c0c9e01ebe6b55913c519ad6086bcaec1a89f8308f3effacd435f"
		logic_hash = "fd6ae610a4d2cbf02aae2302d181d07780e723ac7e61b5aa3fd18ba834160729"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "bd50e4b3d9999d68574903bd9ec144be7456908658639852480418315903da5b"
		threat_name = "Windows.VulnDriver.XTier"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 73 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}