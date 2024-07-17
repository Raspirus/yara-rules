
rule ELASTIC_Windows_Vulndriver_Rtkio_5693E967 : FILE
{
	meta:
		description = "Name: rtkiow10x64.sys"
		author = "Elastic Security"
		id = "5693e967-dbe4-457c-8b0c-404774871ac0"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Rtkio.yar#L64-L83"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ab8f2217e59319b88080e052782e559a706fa4fb7b8b708f709ff3617124da89"
		logic_hash = "4cbc7a52de7f610cdb12bf40a9099bcfae818dcb5e4119a8c34499433aeebd7e"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "4de76b2d42b523c4bfefeee8905e8f431168cb59e18049563f9942e97c276e46"
		threat_name = "Windows.VulnDriver.Rtkio"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 31 00 30 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}