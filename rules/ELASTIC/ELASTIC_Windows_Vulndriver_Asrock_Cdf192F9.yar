rule ELASTIC_Windows_Vulndriver_Asrock_Cdf192F9 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Asrock (Windows.VulnDriver.Asrock)"
		author = "Elastic Security"
		id = "cdf192f9-c62f-4e00-b6a9-df85d10fee99"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Asrock.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d"
		logic_hash = "2f844b6d3fa19fd39097395175162578ad71d78c61dad104efd320cd8285fa6b"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "f27c61c67b51ab88994742849dcd1311064ef0cacddb57503336d08f45059060"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\AsrDrv103.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}