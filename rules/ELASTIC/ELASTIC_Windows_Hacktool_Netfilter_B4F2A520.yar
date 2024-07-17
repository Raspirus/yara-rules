rule ELASTIC_Windows_Hacktool_Netfilter_B4F2A520 : FILE
{
	meta:
		description = "Detects Windows Hacktool Netfilter (Windows.Hacktool.NetFilter)"
		author = "Elastic Security"
		id = "b4f2a520-88bf-447e-bbc4-5d8bfd2c9753"
		date = "2022-04-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_NetFilter.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5d0d5373c5e52c4405f4bd963413e6ef3490b7c4c919ec2d4e3fb92e91f397a0"
		logic_hash = "520d2194593f1622a3b905fe182a0773447a4eee3472e7701cce977f5bf4fbae"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "1d8da6f78149e2db6b54faa381ce8eb285930226a5b4474e04937893c831809f"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\netfilterdrv.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}