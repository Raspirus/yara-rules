rule SIGNATURE_BASE_APT_Tick_Sysmon_Loader_Jun18 : FILE
{
	meta:
		description = "Detects Sysmon Loader from Tick group incident - Weaponized USB"
		author = "Florian Roth (Nextron Systems)"
		id = "eae013c3-4774-5342-bd1a-5f2825612747"
		date = "2018-06-23"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-tick-group-weaponized-secure-usb-drives-target-air-gapped-critical-systems/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_tick_weaponized_usb.yar#L13-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e6256269409322a4f48bfdaafc52f5ec83602cf66f2e3b8d83ed5175e1dc506f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "31aea8630d5d2fcbb37a8e72fe4e096d0f2d8f05e03234645c69d7e8b59bb0e8"

	strings:
		$x1 = "SysMonitor_3A2DCB47" fullword ascii
		$s1 = "msxml.exe" fullword ascii
		$s2 = "wins.log" fullword ascii
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" fullword ascii
		$s4 = "%2d-%2d-%2d-%2d" fullword ascii
		$s5 = "%USERPROFILE%" fullword ascii
		$s6 = "Windows NT" fullword ascii
		$s7 = "device monitor" fullword ascii
		$s8 = "\\Accessories" ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="c5bb16e79fb500c430edce9481ae5b2b" or $x1 or 6 of them )
}