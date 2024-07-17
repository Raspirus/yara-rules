rule ELASTIC_Windows_Vulndriver_Rtkio_13B3C88B : FILE
{
	meta:
		description = "Name: rtkio.sys"
		author = "Elastic Security"
		id = "13b3c88b-daa7-4402-ad31-6fc7d4064087"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Rtkio.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82"
		logic_hash = "1e37650292884e28dcc51c42bc1b1d1e8efc13b0727f7865ff1dc7b8e1a72380"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "3788e6a7a759796a2675116e4d291324f97114773cf53345f15796566266f702"
		threat_name = "Windows.VulnDriver.Rtkio"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}