rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Handle_Mod_0X51_Command : FILE
{
	meta:
		description = "Detects the code bytes used to check commands sent to module ID 0x51 and notable strings relating to the Cyclops Blink update process"
		author = "NCSC"
		id = "a6800aed-27dc-5d01-b005-1eb4a62344a3"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L176-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8a68f4a5f5b7a45819e9a198881aa41b75a65181b63788c8b824b339bfd6fc67"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$cmd_check = {88 1F [2] 54 00 06 3E 2F 80 00 (01|02|03) }
		$path1 = "/etc/wg/configd-hash.xml"
		$path2 = "/etc/wg/config.xml"
		$mnt_arg1 = "ext2"
		$mnt_arg2 = "errors=continue"
		$mnt_arg3 = {38 C0 0C 20}
		$mnt_arg4 = {38 C0 0C 21}

	condition:
		( uint32(0)==0x464c457f) and (#cmd_check==3) and ((@cmd_check[3]-@cmd_check[1])<0x200) and ( all of ($path*)) and ( all of ($mnt_arg*))
}