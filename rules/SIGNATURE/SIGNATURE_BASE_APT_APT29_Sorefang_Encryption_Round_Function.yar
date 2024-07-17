
rule SIGNATURE_BASE_APT_APT29_Sorefang_Encryption_Round_Function : FILE
{
	meta:
		description = "Rule to detect SoreFang based on the encryption round function"
		author = "NCSC"
		id = "0be1c084-c8df-5920-a320-90364a7fb542"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L201-L214"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "c4979b7ec31581b43b6975be5d4b1bfa5562e5fe25bbb51bb7c388550ed80ac6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = { 8A E9 8A FB 8A 5D 0F 02 C9 88 45 0F FE C1 0F BE C5 88 6D F3 8D
            14 45 01 00 00 00 0F AF D0 0F BE C5 0F BE C9 0F AF C8 C1 FA 1B C0 E1 05 0A D1 8B 4D EC 0F BE C1 89 55 E4 8D 14 45 01 00 00 00 0F AF D0 8B C1}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}