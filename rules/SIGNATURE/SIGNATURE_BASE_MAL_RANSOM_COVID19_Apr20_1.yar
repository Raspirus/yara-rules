rule SIGNATURE_BASE_MAL_RANSOM_COVID19_Apr20_1 : FILE
{
	meta:
		description = "Detects ransomware distributed in COVID-19 theme"
		author = "Florian Roth (Nextron Systems)"
		id = "fc723d1f-e969-5af6-af57-70d00bf797f4"
		date = "2020-04-15"
		modified = "2023-12-05"
		reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_covid_ransom.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9b32ce1dff9d27c5f7541de97cd1198b0d837a69ee260b327c66a22ca6f30091"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"

	strings:
		$s1 = "/savekey.php" wide
		$op1 = { 3f ff ff ff ff ff 0b b4 }
		$op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 }
		$op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 }

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 2 of them
}