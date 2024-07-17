
rule ELASTIC_Windows_Vulndriver_Elrawdisk_F9Fd1A80 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Elrawdisk (Windows.VulnDriver.ElRawDisk)"
		author = "Elastic Security"
		id = "f9fd1a80-048f-437f-badb-85d984af202d"
		date = "2022-10-07"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_ElRawDisk.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ed4f2b3db9a79535228af253959a0749b93291ad8b1058c7a41644b73035931b"
		logic_hash = "43f9f1f6ad6c1defe2f0d6dd0cd380bea1a8ead19bc0bf203bdfe4f83b9c284d"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "3d9dedd033cf07920eaa99b0d1fb654057def2bcef10080b45e1e8a285db8a4e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\elrawdsk.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}