rule ELASTIC_Windows_Vulndriver_Biostar_E0B6Cf55 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Biostar (Windows.VulnDriver.Biostar)"
		author = "Elastic Security"
		id = "e0b6cf55-c97d-4799-88a6-30ab0e880b0b"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Biostar.yar#L67-L85"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "73327429c505d8c5fd690a8ec019ed4fd5a726b607cabe71509111c7bfe9fc7e"
		logic_hash = "dccbf6fa46de1a8bc6438578b651055e2d02d15bd04461be74059e6fde40fca3"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "c38c456a008b847c42c45f824b125e7308b8aa41771d3db3d540690b13147abc"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\BS_RCIO.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}