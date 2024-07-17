
rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Handle_Mod_0Xf_Command : FILE
{
	meta:
		description = "Detects the code bytes used to check module ID 0xf control flags and a format string used for file content upload"
		author = "NCSC"
		id = "36646b7a-389d-5fd9-88a1-e43e7224763a"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L128-L150"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6e3eebe404c8cd24e1e16eb3c881b1eda78ba6b365bf89c2557329e6f89396ac"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {54 00 06 3E 54 00 07 FE 54 00 06 3E 2F 80 00 00}
		$ = {54 00 06 3E 54 00 07 BC 2F 80 00 00}
		$ = {54 00 06 3E 54 00 07 7A 2F 80 00 00}
		$ = {54 00 06 3E 54 00 06 F6 2F 80 00 00}
		$ = "file:%s\n" fullword

	condition:
		( uint32(0)==0x464c457f) and ( all of them )
}