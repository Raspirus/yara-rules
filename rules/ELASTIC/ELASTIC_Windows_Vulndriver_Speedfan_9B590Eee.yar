
rule ELASTIC_Windows_Vulndriver_Speedfan_9B590Eee : FILE
{
	meta:
		description = "Subject: Sokno S.R.L."
		author = "Elastic Security"
		id = "9b590eee-5938-4293-afac-c9e730753413"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Speedfan.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c"
		logic_hash = "6f75c0e6b89dd1ceb85c73b7e51fd261ca2804e14a5f8ed6ce3352b3f1bcdfe4"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "c58a8c3bfa710896c35262cc880b9afbadcdfdd73d9969c707e7b5b64e6a70b5"
		threat_name = "Windows.VulnDriver.Speedfan"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}