
rule ELASTIC_Windows_Vulndriver_Fidpci_Cb7F69B5 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Fidpci (Windows.VulnDriver.Fidpci)"
		author = "Elastic Security"
		id = "cb7f69b5-5421-493b-adf7-75130d19b001"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Fidpci.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46"
		logic_hash = "459429fb4e5156890f19c451e48676c9cd06eaab1c2eaea9236737c795086b5f"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "19da3f67e302d0a70d40533553a19ba91a99a83609c01c8f296834a93fa325e2"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\fidpcidrv64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}