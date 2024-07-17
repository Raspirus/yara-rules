
rule ELASTIC_Windows_Vulndriver_Lha_F72Bff9A : FILE
{
	meta:
		description = "Name: LHA.sys"
		author = "Elastic Security"
		id = "f72bff9a-046c-4e02-9e11-4787c8aada75"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Lha.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e75714f8e0ff45605f6fc7689a1a89c7dcd34aab66c6131c63fefaca584539cf"
		logic_hash = "cea05432b47cf14982bda74476c8c8582068c22fe7dec6468c9756c20412dca2"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "3b464386a60747131012d8380a34bed9329b02ac5cdc7b69b951f4f681243f35"
		threat_name = "Windows.VulnDriver.Lha"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 48 00 41 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}