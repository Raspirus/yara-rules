rule ELASTIC_Windows_Vulndriver_Xtier_6A7De49F : FILE
{
	meta:
		description = "Name: NCPL.SYS, Version: 3.1.12.0"
		author = "Elastic Security"
		id = "6a7de49f-1a31-4ce0-b4b1-cdc670bfdf18"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_XTier.yar#L67-L87"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "26c86227d3f387897c1efd77dc711eef748eb90be84149cb306e3d4c45cc71c7"
		logic_hash = "de0d25377103d50b33a95a804b9c3eb9ef221d56fa1dfda0a32f14dcd95ee4b1"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "fb012fd29d00b1dc06353ebfff62d29cc9d86549d8af10b049213256cbcab09e"
		threat_name = "Windows.VulnDriver.XTier"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 43 00 50 00 4C 00 2E 00 53 00 59 00 53 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x0c][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0b][\x00-\x00]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}