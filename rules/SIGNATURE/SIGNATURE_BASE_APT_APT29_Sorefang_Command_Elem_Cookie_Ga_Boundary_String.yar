rule SIGNATURE_BASE_APT_APT29_Sorefang_Command_Elem_Cookie_Ga_Boundary_String : FILE
{
	meta:
		description = "Rule to detect SoreFang based on scheduled task element and Cookie header/boundary strings"
		author = "NCSC"
		id = "3c6ffbad-9b39-5518-aa66-d76531ddb9ea"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L185-L199"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "65b31a12d8abb88fbb99fcc6b2707bec90e4edc35d0cf21903213eda5cacec88"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "<Command>" wide
		$ = "Cookie:_ga="
		$ = "------974767299852498929531610575"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 2 of them
}