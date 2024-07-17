rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Default_Config_Values : FILE
{
	meta:
		description = "Detects the code bytes used to set default Cyclops Blink configuration values"
		author = "NCSC"
		id = "04067609-1173-51f2-907f-2a236aae6c7c"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L152-L174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "180993057c110c0c0327b673c6d6e251534012de51cf6475838691e0942a1aa8"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {38 00 00 19 90 09 01 A4}
		$ = {3C 00 00 01 60 00 80 00 90 09 01 A8}
		$ = {38 00 40 00 90 09 01 AC}
		$ = {38 00 01 0B 90 09 01 B0}
		$ = {38 00 27 11 90 09 01 C0}

	condition:
		( uint32(0)==0x464c457f) and (3 of them )
}