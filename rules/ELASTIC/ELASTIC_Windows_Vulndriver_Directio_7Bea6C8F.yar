rule ELASTIC_Windows_Vulndriver_Directio_7Bea6C8F : FILE
{
	meta:
		description = "Detects Windows Vulndriver Directio (Windows.VulnDriver.DirectIo)"
		author = "Elastic Security"
		id = "7bea6c8f-7006-4994-be21-614e3cf1ec76"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_DirectIo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1dadd707c55413a16320dc70d2ca7784b94c6658331a753b3424ae696c5d93ea"
		logic_hash = "bc87ede24c688565258859287141ddffb3bcfb0cc6d4fcbc08827c48bb897580"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "6ad4cca6b8345825ef706d2e933508caf047a7d15a7f5b2f8d3d8a6f7c24b93d"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\DirectIo.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}