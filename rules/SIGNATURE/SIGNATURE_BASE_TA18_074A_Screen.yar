
rule SIGNATURE_BASE_TA18_074A_Screen : FILE
{
	meta:
		description = "Detects malware mentioned in TA18-074A"
		author = "Florian Roth (Nextron Systems)"
		id = "789ee5e5-83c3-5137-a078-ff230dbf8fcd"
		date = "2018-03-16"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta18_074A.yar#L34-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e96f70e3d9c7ff5812724111788365c47e2b478a35b39771c12a3d3636a6a020"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"

	strings:
		$s1 = "screen.exe" fullword wide
		$s2 = "PlatformInvokeUSER32" fullword ascii
		$s3 = "GetDesktopImageF" fullword ascii
		$s4 = "PlatformInvokeGDI32" fullword ascii
		$s5 = "Too many arguments, going to store in current dir" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 3 of them
}