rule SIGNATURE_BASE_APT_Sidewinder_NET_Loader_Aug_2020_1_1 : FILE
{
	meta:
		description = "Detected the NET loader used by SideWinder group (August 2020)"
		author = "Arkbird_SOLG"
		id = "61d96e2a-3a43-586f-85bc-a2c53b1318e6"
		date = "2020-08-24"
		modified = "2023-12-05"
		reference = "https://twitter.com/ShadowChasing1/status/1297902086747598852"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sidewinder.yar#L4-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5ee7029143c589f26e6c325e163bfac85507c950f09778bd51ec2bdf4d4263fa"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "4a0947dd9148b3d5922651a6221afc510afcb0dfa69d08ee69429c4c75d4c8b4"

	strings:
		$a1 = "DUSER.dll" fullword wide
		$s1 = "UHJvZ3JhbQ==" fullword wide
		$s2 = "U3RhcnQ=" fullword wide
		$s3 = ".tmp           " fullword wide
		$s4 = "FileRipper" fullword ascii
		$s5 = "copytight @" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <4KB and $a1 and 3 of ($s*)
}