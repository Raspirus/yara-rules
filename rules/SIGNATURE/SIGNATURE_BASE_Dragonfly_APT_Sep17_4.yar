rule SIGNATURE_BASE_Dragonfly_APT_Sep17_4 : FILE
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "dbc0eebf-fc81-5a0b-b2e0-129d0b40b6f7"
		date = "2017-09-12"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_dragonfly.yar#L91-L109"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "61af81f0cd1eccba3a1000e6715c9715e8e67849e5edd4279728a7e47bd8cb75"
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
		$s5 = "GetDesktopImage" fullword ascii
		$s6 = "Too many arguments, going to store in current dir" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and all of them )
}