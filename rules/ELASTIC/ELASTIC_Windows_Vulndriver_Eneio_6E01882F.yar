
rule ELASTIC_Windows_Vulndriver_Eneio_6E01882F : FILE
{
	meta:
		description = "Detects Windows Vulndriver Eneio (Windows.VulnDriver.EneIo)"
		author = "Elastic Security"
		id = "6e01882f-8394-4e32-8049-fa9c4588b087"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_EneIo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "175eed7a4c6de9c3156c7ae16ae85c554959ec350f1c8aaa6dfe8c7e99de3347"
		logic_hash = "144ac5375cb637b6301a2275f2412fbd0d0c5fb23105c7cce5aa7912cf68fa2c"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "8077212bfbadc7f47f2eb76f123a6e4bcda12009293cb975bbeaba77f8c9dcd0"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\Release\\EneIo.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}