
rule ELASTIC_Windows_Hacktool_Gmer_8Aabdd5E : FILE
{
	meta:
		description = "Detects Windows Hacktool Gmer (Windows.Hacktool.Gmer)"
		author = "Elastic Security"
		id = "8aabdd5e-1ce7-4257-abaa-8d02dc6856a6"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Gmer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "18c909a2b8c5e16821d6ef908f56881aa0ecceeaccb5fa1e54995935fcfd12f7"
		logic_hash = "acdab89a7703a743927cec60fbc84af2fd469403bee6f211c865fb96e9c92498"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "960721d4d111a670907fe7d3ce01dfd134ad03a2d8440a945c75a7d46de46238"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\gmer64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}