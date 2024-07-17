rule SIGNATURE_BASE_APT_APT29_Sorefang_Encryption_Key_2B62 : FILE
{
	meta:
		description = "Rule to detect SoreFang based on hardcoded encryption key"
		author = "NCSC"
		id = "9a7abad7-1cfa-52c8-9416-47cb80486714"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L155-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "39ad6de70883fbe0377379c3cab15962372793043ebbf4054efb7cee3aff9104"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "2b6233eb3e872ff78988f4a8f3f6a3ba"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}