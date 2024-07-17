rule SIGNATURE_BASE_Winagent_Badpatch_1 : FILE
{
	meta:
		description = "Detects samples mentioned in BadPatch report"
		author = "Florian Roth (Nextron Systems)"
		id = "732792ed-cb70-5b69-8457-f54177e4609e"
		date = "2017-10-20"
		modified = "2023-12-05"
		reference = "https://goo.gl/RvDwwA"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_bad_patch.yar#L11-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "568086edb8884877f9dcb0cffa1e4c05164e6884bf80ce50692cedfa3e8d5750"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "285998bce9692e46652529685775aa05e3a5cb93ee4e65d021d2231256e92813"

	strings:
		$x1 = "J:\\newPatch\\downloader\\" wide
		$x2 = "L:\\rashed\\New code\\" wide
		$x3 = ":\\newPatch\\last version\\" wide
		$x4 = "\\Microsoft\\Microsoft\\Microsoft1.log" wide
		$x5 = "\\Microsoft\\Microsoft\\Microsoft.log" wide
		$x6 = "\\Microsoft\\newPP.exe" wide
		$x7 = " (this is probably a proxy server error)." fullword wide
		$x8 = " :Old - update patch and check anti-virus.. " fullword wide
		$x9 = "PatchNotExit-- download now.. " fullword wide
		$x10 = "PatchNotExit-- Check Version" fullword wide
		$x11 = "PatchNotExit-- Version Patch" fullword wide
		$s1 = "downloader " fullword wide
		$s2 = "DelDownloadFile" fullword ascii
		$s3 = "downloadFile" fullword ascii
		$s4 = "downloadUpdate" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and (1 of ($x*) or 4 of them ))
}