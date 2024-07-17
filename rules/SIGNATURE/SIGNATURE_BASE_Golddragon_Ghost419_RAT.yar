rule SIGNATURE_BASE_Golddragon_Ghost419_RAT : FILE
{
	meta:
		description = "Detects Ghost419 RAT from Gold Dragon report"
		author = "Florian Roth (Nextron Systems)"
		id = "8ac951d5-4a18-50c5-8ded-8a0a6b585fd6"
		date = "2018-02-03"
		modified = "2023-01-06"
		reference = "https://goo.gl/rW1yvZ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_golddragon.yar#L46-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b953c5e21c332add4ff3b8fef9d623904eb929b0e7fc86e6c7109cd81bc3819b"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "45bfa1327c2c0118c152c7192ada429c6d4ae03b8164ebe36ab5ba9a84f5d7aa"
		hash2 = "ee7a9a7589cbbcac8b6bf1a3d9c5d1c1ada98e68ac2f43ff93f768661b7e4a85"
		hash3 = "dee482e5f461a8e531a6a7ea4728535aafdc4941a8939bc3c55f6cb28c46ad3d"
		hash4 = "2df9e274ce0e71964aca4183cec01fb63566a907981a9e7384c0d73f86578fe4"
		hash5 = "111ab6aa14ef1f8359c59b43778b76c7be5ca72dc1372a3603cd5814bfb2850d"
		hash6 = "0ca12b78644f7e4141083dbb850acbacbebfd3cfa17a4849db844e3f7ef1bee5"
		hash7 = "ae1b32aac4d8a35e2c62e334b794373c7457ebfaaab5e5e8e46f3928af07cde4"
		hash8 = "c54837d0b856205bd4ae01887aae9178f55f16e0e1a1e1ff59bd18dbc8a3dd82"
		hash9 = "db350bb43179f2a43a1330d82f3afeb900db5ff5094c2364d0767a3e6b97c854"

	strings:
		$x2 = "WebKitFormBoundarywhpFxMBe19cSjFnG" ascii
		$x3 = "\\Microsoft\\HNC\\" ascii
		$x4 = "\\anternet abplorer" ascii
		$x5 = "%s\\abxplore.exe" fullword ascii
		$x6 = "GHOST419" fullword ascii
		$x7 = "I,m Online. %04d - %02d - %02d - %02d - %02d" fullword ascii
		$x8 = "//////////////////////////regkeyenum//////////////" ascii
		$s0 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
		$s1 = "www.GoldDragon.com" fullword ascii
		$s2 = "/c systeminfo >> %s" fullword ascii
		$s3 = "/c dir %s\\ >> %s" fullword ascii
		$s4 = "DownLoading %02x, %02x, %02x" fullword ascii
		$s5 = "Tran_dll.dll" fullword ascii
		$s6 = "MpCmdRunkr.dll" fullword ascii
		$s7 = "MpCmdRun.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and ((pe.exports("ExportFunction") and pe.number_of_exports==1) or (1 of ($x*) and 1 of ($s*)) or 3 of them )
}