
rule ELASTIC_Windows_Hacktool_Capcom_7Abae448 : FILE
{
	meta:
		description = "Subject: CAPCOM Co.,Ltd."
		author = "Elastic Security"
		id = "7abae448-0ebc-433f-b368-0b8560da7197"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Capcom.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24"
		logic_hash = "88f25c479cc8970e05ef9d08143afbbbfa17322f34379ba571e3a09105b33ee0"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "965e85fc3b2a21aef84c7c2bd59708b121d9635ce6bab177014b28fb00102884"
		threat_name = "Windows.Hacktool.Capcom"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 43 41 50 43 4F 4D 20 43 6F 2E 2C 4C 74 64 2E }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}