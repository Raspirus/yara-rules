rule SIGNATURE_BASE_Hkdoor_Backdoor : FILE
{
	meta:
		description = "Hacker's Door Backdoor"
		author = "Cylance Inc."
		id = "470e5d37-8a5a-500f-b9b9-245b8dc2c4d7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hkdoor.yar#L32-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3fc71c971bf0908e044e3e0ec3f266b8dfaae33bcfbf1b10619375fc7b5e7f5e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "http://www.yythac.com" fullword ascii
		$s2 = "Example:%s 192.168.1.100 139 -p yyt_hac -t 1" fullword ascii
		$s3 = "password-----------The hacker's door's password" fullword ascii
		$s4 = "It is the client of hacker's door %d.%d public version" fullword ascii
		$s5 = "hkdoordll.dll" fullword ascii
		$s6 = "http://www.yythac.com/images/mm.jpg" fullword ascii
		$s7 = "I'mhackeryythac1977" fullword ascii
		$s8 = "yythac.yeah.net" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (4 of ($s*))
}