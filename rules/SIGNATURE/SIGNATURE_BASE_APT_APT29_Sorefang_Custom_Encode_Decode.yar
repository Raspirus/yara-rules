
rule SIGNATURE_BASE_APT_APT29_Sorefang_Custom_Encode_Decode : FILE
{
	meta:
		description = "Rule to detect SoreFang based on the custom encoding/decoding algorithm function"
		author = "NCSC"
		id = "4885a659-bb3a-5e33-99cc-b827931bf58f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L245-L274"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
		logic_hash = "536147bda9603d68748010f9db260af732fe0865a601ae1104538933b19c519b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = { 55 8B EC 8B D1 53 56 8B 75 08 8B DE 80 42 62 FA 8A 4A 62 66 D3
            EB 57 3A 5A 5C 74 0F}
		$ = { 3A 5A 5D 74 0A 3A 5A 58 74 05 3A 5A 59 75 05 FE C1 88 4A 62 8A 
            4A 62 B8 01 00 00 00}
		$ = { 8A 46 62 84 C0 74 3E 3C 06 73 12 0F B6 C0 B9 06 00 00 00 2B C8 
            C6 46 62 06 66 D3 66 60 0F B7 4E 60}
		$ = { 80 3C 38 0D 0F 84 93 01 00 00 C6 42 62 06 8B 56 14 83 FA 10 72 
            04 8B 06}
		$ = { 0F BE 0C 38 8B 45 EC 0F B6 40 5B 3B C8 75 07 8B 55 EC B3 3E}
		$ = { 0F BE 0C 38 8B 45 EC 0F B6 40 5E 3B C8 75 0B 8B 55 EC D0 EB C6 
            42 62 05}
		$ = { 8B 55 EC 0F BE 04 38 0F B6 DB 0F B6 4A 5F 3B C1 B8 3F 00 00 00 
            0F 44 D8}
		$ = { 8A 4A 62 66 8B 52 60 66 D3 E2 0F B6 C3 66 0B D0 8B 45 EC 66 89 
            50 60 8A 45 F3 02 C1 88 45 F3 3C 08 72 2E 04 F8 8A C8 88 45 F3 
            66 D3 EA 8B 4D 08 0F B6 C2 50 }
		$ = { 3A 5A 5C 74 0F 3A 5A 5D 74 0A 3A 5A 58 74 05 3A 5A 59 75 05 FE 
            C1 88 4A 62 }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}