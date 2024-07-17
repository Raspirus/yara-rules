rule SIGNATURE_BASE_APT_APT29_Sorefang_Modify_Alphabet_Custom_Encode : FILE
{
	meta:
		description = "Rule to detect SoreFang based on arguments passed into custom encoding algorithm function"
		author = "NCSC"
		id = "7c5c1be0-ccad-5c8f-a026-445994b1f279"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L231-L243"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "f0f5bcad52b0b15dc74a51973ef2752234bd12d677c846b2f96fe569d906ea3b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = { 33 C0 8B CE 6A 36 6A 71 66 89 46 60 88 46 62 89 46 68 66 89 46
            64 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}