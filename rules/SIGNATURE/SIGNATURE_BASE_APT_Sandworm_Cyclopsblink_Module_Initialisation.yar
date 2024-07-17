rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Module_Initialisation : FILE
{
	meta:
		description = "Detects the code bytes used to initialise the modules built into Cyclops Blink"
		author = "NCSC"
		id = "c81b92c4-3f70-5bbd-acfa-ed1e1d33461d"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L39-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8bde37f642cf07e323beabaacd5c62f8422b451777fc1fc4a6bdf474db49de12"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {94 21 FF F0 93 E1 00 08 7C 3F 0B 78 38 00 00 ?? 7C 03
      03 78 81 61 00 00 8E EB FF F8 7D 61 5B 78 4E 80 00 20}

	condition:
		( uint32(0)==0x464c457f) and ( any of them )
}