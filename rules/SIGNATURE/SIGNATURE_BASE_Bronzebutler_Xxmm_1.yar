rule SIGNATURE_BASE_Bronzebutler_Xxmm_1 : FILE
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		author = "Florian Roth (Nextron Systems)"
		id = "0e413e3a-fb61-58bc-9ecb-4ef76e83a7f3"
		date = "2017-10-14"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L115-L140"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "eb9c12cbe2fe132a9588b744d10caee12716f622c31da8a1cee4c0f88d693e8e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7197de18bc5a4c854334ff979f3e4dafa16f43d7bf91edfe46f03e6cc88f7b73"

	strings:
		$x1 = "\\Release\\ReflectivLoader.pdb" ascii
		$x3 = "\\Projects\\xxmm2\\Release\\" ascii
		$x5 = "http://127.0.0.1/phptunnel.php" fullword ascii
		$s1 = "xxmm2.exe" fullword ascii
		$s2 = "\\AvUpdate.exe" wide
		$s3 = "stdapi_fs_file_download" fullword ascii
		$s4 = "stdapi_syncshell_open" fullword ascii
		$s5 = "stdapi_execute_sleep" fullword ascii
		$s6 = "stdapi_syncshell_kill" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or 4 of them )
}