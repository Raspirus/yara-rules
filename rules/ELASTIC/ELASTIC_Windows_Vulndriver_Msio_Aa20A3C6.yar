
rule ELASTIC_Windows_Vulndriver_Msio_Aa20A3C6 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Msio (Windows.VulnDriver.MsIo)"
		author = "Elastic Security"
		id = "aa20a3c6-c07c-49ef-be33-b61e612be42a"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_MsIo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2270a8144dabaf159c2888519b11b61e5e13acdaa997820c09798137bded3dd6"
		logic_hash = "3b383934dc91536f69e2c6cb2cf2054c5f8a08766ecf1d1804c57f3a2c39c1c2"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "28136b3928fa2c13dc3950df4b71f01f0d2e3977ca131df425096ec36fe6aad1"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\MsIo32.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}