
rule SIGNATURE_BASE_APT_APT29_Sorefang_Add_Random_Commas_Spaces : FILE
{
	meta:
		description = "Rule to detect SoreFang based on function that adds commas and spaces"
		author = "NCSC"
		id = "9a89c619-6309-500f-b4dc-c8a3e8fc4417"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L216-L229"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "046e222aabc9e596d9536702521b4729d990e1f327ded004ca984b73a8511a83"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = { E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B CE 83 FA 04 7E 09 6A
            02 68 ?? ?? ?? ?? EB 07 6A 01 68 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}