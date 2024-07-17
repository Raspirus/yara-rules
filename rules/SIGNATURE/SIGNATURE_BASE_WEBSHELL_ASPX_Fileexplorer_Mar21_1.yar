rule SIGNATURE_BASE_WEBSHELL_ASPX_Fileexplorer_Mar21_1 : FILE
{
	meta:
		description = "Detects Chopper like ASPX Webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "edcaa2a8-6fea-584e-90c2-307a2dfc9f7f"
		date = "2021-03-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium.yar#L363-L397"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7b4ffd222b38e76455fff2650b72bdcaff281323103f342b427013cd3fffdc21"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"

	strings:
		$x1 = "<span style=\"background-color: #778899; color: #fff; padding: 5px; cursor: pointer\" onclick=" ascii
		$xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64
               20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20
               49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72
               20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73
               73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74
               42 6F 78 20 49 44 3D }
		$xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C
               3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ??
               ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20
               6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62
               65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46
               69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61
               62 65 6C 3E 3C 25 2D 2D }
		$r1 = "(Request.Form[" ascii
		$s1 = ".Text + \" Created!\";" ascii
		$s2 = "DriveInfo.GetDrives()" ascii
		$s3 = "Encoding.UTF8.GetString(FromBase64String(str.Replace(" ascii
		$s4 = "encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))));;"

	condition:
		uint16(0)==0x253c and filesize <100KB and (1 of ($x*) or 2 of them ) or 4 of them
}