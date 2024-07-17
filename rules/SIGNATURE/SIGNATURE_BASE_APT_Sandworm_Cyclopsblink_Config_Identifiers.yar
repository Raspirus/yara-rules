rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Config_Identifiers : FILE
{
	meta:
		description = "Detects the initial characters used to identify Cyclops Blink configuration data"
		author = "NCSC"
		id = "db5b3a4a-82c2-500a-88f6-340b3392eac8"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L106-L126"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6fa39442d717a69dd6f31a4bb2e5865c3f16156ce24a2b419d95ed751bb0d8ee"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {3C 00 3C 6B 60 00 3A 20 90 09 00 00}
		$ = {3C 00 3C 63 60 00 3A 20 90 09 00 00}
		$ = {3C 00 3C 73 60 00 3A 20 90 09 00 00}

	condition:
		( uint32(0)==0x464c457f) and ( all of them )
}