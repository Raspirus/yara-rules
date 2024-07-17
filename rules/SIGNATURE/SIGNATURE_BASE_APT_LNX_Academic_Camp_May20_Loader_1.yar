
rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Loader_1 : FILE
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		id = "cda65abd-d918-5ee6-8f4a-554d47532d76"
		date = "2020-05-16"
		modified = "2023-12-05"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_academic_data_centers_camp_may20.yar#L20-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a73883f9fdf3d53694d9f9efec5f8f15994c5fd80c5f2a87b1741db6b954a023"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"

	strings:
		$sc1 = { C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A 
               C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01 }
		$sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D }

	condition:
		uint16(0)==0x457f and filesize <10KB and all of them
}