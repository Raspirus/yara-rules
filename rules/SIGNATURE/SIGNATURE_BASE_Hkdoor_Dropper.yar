rule SIGNATURE_BASE_Hkdoor_Dropper : FILE
{
	meta:
		description = "Hacker's Door Dropper"
		author = "Cylance Inc."
		id = "8c8171b9-6256-591a-8f74-abac1cb9a50b"
		date = "2018-01-01"
		modified = "2023-01-07"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hkdoor.yar#L53-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "521836ff95142d276152687f7c36e8f503f168f101976022431efd13a6adf7e4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "The version of personal hacker's door server is" fullword ascii
		$s2 = "The connect back interval is %d (minutes)" fullword ascii
		$s3 = "I'mhackeryythac1977" fullword ascii
		$s4 = "Welcome to http://www.yythac.com" fullword ascii
		$s5 = "SeLoadDriverPrivilege" fullword ascii
		$s6 = "\\drivers\\ntfs.sys" ascii
		$s7 = "kifes" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (4 of ($s*)) and pe.number_of_resources>0 and for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type_string=="B\x00I\x00N\x00" and uint16(pe.resources[i].offset)==0x5A4D) and pe.imports("KERNEL32.dll","FindResourceW") and pe.imports("KERNEL32.dll","LoadResource")
}