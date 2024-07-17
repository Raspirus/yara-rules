rule SIGNATURE_BASE_Lazarus_Dec_17_2 : FILE
{
	meta:
		description = "Detects Lazarus malware from incident in Dec 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "45127fb5-0f70-5140-acd9-46147d365dfe"
		date = "2017-12-20"
		modified = "2023-12-05"
		reference = "https://goo.gl/8U6fY2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec17.yar#L31-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "273cd54a0c3ecf53893de0ef9c41d784725eea6cc843e04df01cd8f29d61a797"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cbebafb2f4d77967ffb1a74aac09633b5af616046f31dddf899019ba78a55411"
		hash2 = "9ca3e56dcb2d1b92e88a0d09d8cab2207ee6d1f55bada744ef81e8b8cf155453"

	strings:
		$s1 = "SkypeSetup.exe" fullword wide
		$s2 = "%s\\SkypeSetup.exe" fullword ascii
		$s3 = "Skype Technologies S.A." fullword wide
		$a1 = "Microsoft Code Signing PCA" ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <7000KB and ( all of ($s*) and not $a1)
}