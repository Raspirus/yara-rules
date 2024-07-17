rule SIGNATURE_BASE_Oilrig_Ismagent_Campaign_Samples1 : FILE
{
	meta:
		description = "Detects OilRig malware from Unit 42 report in October 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "237fe7af-a2ab-51ae-bc96-3af46b08622a"
		date = "2017-10-18"
		modified = "2023-12-05"
		reference = "https://goo.gl/JQVfFP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_oilrig_oct17.yar#L42-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d7e659440e3abc7355f2e21ea8f63cfb7b17b5715e4575bdccf9d646ed47db20"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "119c64a8b35bd626b3ea5f630d533b2e0e7852a4c59694125ff08f9965b5f9cc"
		hash2 = "0ccb2117c34e3045a4d2c0d193f1963c8c0e8566617ed0a561546c932d1a5c0c"

	strings:
		$s1 = "###$$$TVqQAAMAAAAEAAAA" ascii
		$s2 = "C:\\Users\\J-Win-7-32-Vm\\Desktop\\error.jpg" fullword wide
		$s3 = "$DATA = [System.Convert]::FromBase64String([IO.File]::ReadAllText('%Base%'));[io.file]::WriteAllBytes(" ascii
		$s4 = " /c echo powershell > " fullword wide ascii
		$s5 = "\\Libraries\\servicereset.exe" wide
		$s6 = "%DestFolder%" fullword wide ascii

	condition:
		uint16(0)==0xcfd0 and filesize <3000KB and 2 of them
}