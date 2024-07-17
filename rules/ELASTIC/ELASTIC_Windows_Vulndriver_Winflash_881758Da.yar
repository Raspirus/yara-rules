rule ELASTIC_Windows_Vulndriver_Winflash_881758Da : FILE
{
	meta:
		description = "Detects Windows Vulndriver Winflash (Windows.VulnDriver.WinFlash)"
		author = "Elastic Security"
		id = "881758da-760c-4c50-81f2-8bd698972ba2"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_WinFlash.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8596ea3952d84eeef8f5dc5b0b83014feb101ec295b2d80910f21508a95aa026"
		logic_hash = "a46ac1f19ba5d9543c88434575870b61fbb935cd4c4e28cb80a077502af7d2db"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "1c64ee1c3fc6bf93e207810a473367c404c824d0eaba15910b00016e23d53637"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\WinFlash64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}