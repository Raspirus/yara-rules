rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_17 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "e314a893-1ef5-5d5f-b056-af25765c0b70"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L319-L343"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0724e07614e704d9ac8a1ae4aecfcf3d9800dde6f83eeecc8427ab6205e321a6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "05036de73c695f59adf818d3c669c48ce8626139d463b8a7e869d8155e5c0d85"
		hash2 = "08d8c610e1ec4a02364cb53ba44e3ca5d46e8a177a0ecd50a1ef7b5db252701d"
		hash3 = "14535607d9a7853f13e8bf63b629e3a19246ed9db6b4d2de2ca85ec7a7bee140"

	strings:
		$x1 = "c:\\users\\administrator\\desktop\\code\\skeyman2\\" ascii
		$x2 = "\\SkeyMan2.pdb" ascii
		$x3 = "\\\\.\\Pnpkb" fullword ascii
		$s1 = "\\DosDevices\\Pnpkb" wide
		$s2 = "\\DosDevices\\PnpKb" wide
		$s3 = "\\Driver\\kbdhid" wide
		$s4 = "\\Device\\PnpKb" wide
		$s5 = "Microsoft  Windows Operating System" fullword wide
		$s6 = "hDevice == INVALID_HANDLE_VALUE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (1 of ($x*) and 1 of ($s*))
}