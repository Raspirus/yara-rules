rule SIGNATURE_BASE_APT_APT29_Sorefang_Remove_Chars_Comma_Space_Dot : FILE
{
	meta:
		description = "Rule to detect SoreFang based on function that removes commas, spaces and dots"
		author = "NCSC"
		id = "c15779b0-6a5e-5345-94ad-95615b567f1f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L276-L289"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "652607e0cfe6f5ad6ede169e28f63e8262fc37cbc7baa2525e52e79572d9a468"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = {8A 18 80 FB 2C 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}
		$ = {8A 18 80 FB 2E 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}
		$ = {8A 18 80 FB 20 74 03 88 19 41 42 40 3B D6 75 F0 8B 5D 08}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}