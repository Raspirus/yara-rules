rule SIGNATURE_BASE_Hkdoor_Backdoor_Dll : FILE
{
	meta:
		description = "Hacker's Door Backdoor DLL"
		author = "Cylance Inc."
		id = "470e5d37-8a5a-500f-b9b9-245b8dc2c4d7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hkdoor.yar#L11-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "77901d1f2d6c53161c79b50ef20eeb424bf1b8b32906302ca10f3c4b82a58e2a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "The version of personal hacker's door server is" fullword ascii
		$s2 = "The connect back interval is %d (minutes)" fullword ascii
		$s3 = "I'mhackeryythac1977" fullword ascii
		$s4 = "Welcome to http://www.yythac.com" fullword ascii
		$s5 = "SeLoadDriverPrivilege" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (3 of ($s*)) and pe.characteristics&pe.DLL and pe.imports("ws2_32.dll","WSAStartup") and pe.imports("ws2_32.dll","sendto")
}