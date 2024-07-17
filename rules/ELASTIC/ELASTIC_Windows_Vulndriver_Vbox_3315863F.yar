
rule ELASTIC_Windows_Vulndriver_Vbox_3315863F : FILE
{
	meta:
		description = "Subject: innotek GmbH"
		author = "Elastic Security"
		id = "3315863f-668c-47ec-86c7-85d50c3b97d9"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_VBox.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "42d926cfb3794f9b1e3cb397498696cb687f505e15feb9df11b419c49c9af498"
		logic_hash = "ba4e6a94516e36dcd6140b6732d959703e2c58a79add705b9260001ea26db738"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "b0aea1369943318246f1601f823c72f92a0155791661dadc4c854827c295e4bf"
		threat_name = "Windows.VulnDriver.VBox"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}