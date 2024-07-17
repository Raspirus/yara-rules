rule ELASTIC_Windows_Vulndriver_Msio_Ce0Bda23 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Msio (Windows.VulnDriver.MsIo)"
		author = "Elastic Security"
		id = "ce0bda23-087c-49ec-b064-88b1d45e785a"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_MsIo.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "43ba8d96d5e8e54cab59d82d495eeca730eeb16e4743ed134cdd495c51a4fc89"
		logic_hash = "f7fbe0255a006cce42aff61b294512c11e1cceaf11d5c1b6f75b96fb3b155895"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "fe0c380dabec41458a5b5e0d7d38a4f9282f1ef87c51addd954da70d7c8ab1f2"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\MsIo64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}