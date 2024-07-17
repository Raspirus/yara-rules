
rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Eraser_1 : FILE
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		id = "36d17887-9844-5fa4-8a0d-89cc41b2d876"
		date = "2020-05-16"
		modified = "2023-12-05"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_academic_data_centers_camp_may20.yar#L1-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9a0410e86fa8fb8b599e5b8a6508d6889eb6e26600f0ecf222561ac4a169676d"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"

	strings:
		$sc2 = { E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE
               00 00 00 00 89 C7 E8 }
		$sc3 = { E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01
               00 00 00 48 89 C7 E8 }

	condition:
		uint16(0)==0x457f and filesize <60KB and all of them
}