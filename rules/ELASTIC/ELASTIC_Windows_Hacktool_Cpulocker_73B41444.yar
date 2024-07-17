rule ELASTIC_Windows_Hacktool_Cpulocker_73B41444 : FILE
{
	meta:
		description = "Detects Windows Hacktool Cpulocker (Windows.Hacktool.CpuLocker)"
		author = "Elastic Security"
		id = "73b41444-4c17-4fea-b440-fe7b0a086a7f"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_CpuLocker.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dbfc90fa2c5dc57899cc75ccb9dc7b102cb4556509cdfecde75b36f602d7da66"
		logic_hash = "8fb33744326781c51bb6bd18d0574602256b813b62ec8344d5338e6442bb2de0"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "3f90517fbeafdccd37e4b8ab0316a91dd18a911cb1f4ffcd4686ab912a0feab4"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\CPULocker.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}