
rule SIGNATURE_BASE_APT_APT29_Sorefang_Directory_Enumeration_Output_Strings : FILE
{
	meta:
		description = "Rule to detect SoreFang based on formatted string output for directory enumeration"
		author = "NCSC"
		id = "e24dbda1-3d43-52a7-9249-70a648f4913e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L169-L183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "8f029269f5a383737f38af04b05a16a71af5453bffe83e04ac53191eaa49d3e7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "----------All usres directory----------"
		$ = "----------Desktop directory----------"
		$ = "----------Documents directory----------"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 2 of them
}