rule SIGNATURE_BASE_APT_Tick_Homamdownloader_Jun18 : FILE
{
	meta:
		description = "Detects HomamDownloader from Tick group incident - Weaponized USB"
		author = "Florian Roth (Nextron Systems)"
		id = "8ec52cb7-41a4-50a9-9cb1-23bee354680f"
		date = "2018-06-23"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-tick-group-weaponized-secure-usb-drives-target-air-gapped-critical-systems/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_tick_weaponized_usb.yar#L40-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b4c798aa0c71f44f271e710d791c97adcbf9bd28ec87dd1d8d589029e58d1cfb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f817c9826089b49d251b8a09a0e9bf9b4b468c6e2586af60e50afe48602f0bec"

	strings:
		$s1 = "cmd /c hostname >>" fullword ascii
		$s2 = "Mstray.exe" fullword ascii
		$s3 = "msupdata.exe" fullword ascii
		$s5 = "Windows\\CurrentVersion\\run" fullword ascii
		$s6 = "Content-Type: */*" fullword ascii
		$s11 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 3 of them
}