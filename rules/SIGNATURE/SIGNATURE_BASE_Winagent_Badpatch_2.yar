rule SIGNATURE_BASE_Winagent_Badpatch_2 : FILE
{
	meta:
		description = "Detects samples mentioned in BadPatch report"
		author = "Florian Roth (Nextron Systems)"
		id = "648528f0-351c-527e-b516-2c8cae9fb4a3"
		date = "2017-10-20"
		modified = "2023-12-05"
		reference = "https://goo.gl/RvDwwA"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_bad_patch.yar#L41-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "649cfca8fa9d3b9f12b56fd81d4133a00eb5449e67fca2abe85fbfb778912df8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "106deff16a93c4a4624fe96e3274e1432921c56d5a430834775e5b98861c00ea"
		hash2 = "ece76fdf7e33d05a757ef5ed020140d9367c7319022a889923bbfacccb58f4d7"
		hash3 = "cf53fc8c9ce4e5797cc5ac6f71d4cbc0f2b15f2ed43f38048a5273f40bc09876"
		hash4 = "802a39b22dfacdc2325f8a839377c903b4a7957503106ce6f7aed67e824b82c2"
		hash5 = "278dba3857367824fc2d693b7d96cef4f06cb7fdc52260b1c804b9c90d43646d"
		hash6 = "2941f75da0574c21e4772f015ef38bb623dd4d0c81c263523d431b0114dd847e"
		hash7 = "46f3afae22e83344e4311482a9987ed851b2de282e8127f64d5901ac945713c0"
		hash8 = "27752bbb01abc6abf50e1da3a59fefcce59618016619d68690e71ad9d4a3c247"
		hash9 = "050610cfb3d3100841685826273546c829335a5f4e2e4260461b88367ad9502c"

	strings:
		$s1 = "myAction=shell_result&serialNumber=" fullword wide
		$s2 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Login Data.*" wide
		$s3 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" wide
		$s4 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Cookies.*" wide
		$s5 = "newSHELL[" fullword wide
		$s6 = "\\file1.txt" wide
		$s7 = "myAction=newGIF&serialNumber=" fullword wide
		$s8 = "\\Storege1" wide
		$s9 = "\\Microsoft\\mac.txt" wide
		$s10 = "spytube____:" fullword ascii
		$s11 = "0D0700045F5C5B0312045A04041F40014B1D11004A1F19074A141100011200154B031C04" fullword wide
		$s12 = "16161A1000012B162503151851065A1A0007" fullword wide
		$s13 = "-- SysFile...." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 3 of them )
}