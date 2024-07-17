
rule ELASTIC_Windows_Vulndriver_Rtkio_B09Af431 : FILE
{
	meta:
		description = "Name: rtkiow8x64.sys"
		author = "Elastic Security"
		id = "b09af431-307b-40e2-bac5-5865c1ad54c8"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Rtkio.yar#L43-L62"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b205835b818d8a50903cf76936fcf8160060762725bd74a523320cfbd091c038"
		logic_hash = "916a6e63dc4c7ee0bfdf4a455ee467a1d03c1042db60806511aa7cbf3b096190"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "e62a497acc1ee04510aa42ca96c5265e16b3be665f99e7dfc09ecc38055aca5b"
		threat_name = "Windows.VulnDriver.Rtkio"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}