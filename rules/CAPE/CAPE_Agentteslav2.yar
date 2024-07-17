rule CAPE_Agentteslav2 : FILE
{
	meta:
		description = "AgenetTesla Type 2 Keylogger payload"
		author = "ditekshen"
		id = "e60ecee4-0a97-56a1-b21e-47190f8cd1f8"
		date = "2024-03-22"
		modified = "2024-03-22"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/AgentTesla.yar#L43-L67"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "b45296b3b94fa1ff32de48c94329a17402461fb6696e9390565c4dba9738ed78"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "AgentTesla Payload"

	strings:
		$s1 = "get_kbHook" ascii
		$s2 = "GetPrivateProfileString" ascii
		$s3 = "get_OSFullName" ascii
		$s4 = "get_PasswordHash" ascii
		$s5 = "remove_Key" ascii
		$s6 = "FtpWebRequest" ascii
		$s7 = "logins" fullword wide
		$s8 = "keylog" fullword wide
		$s9 = "1.85 (Hash, version 2, native byte-order)" wide
		$cl1 = "Postbox" fullword ascii
		$cl2 = "BlackHawk" fullword ascii
		$cl3 = "WaterFox" fullword ascii
		$cl4 = "CyberFox" fullword ascii
		$cl5 = "IceDragon" fullword ascii
		$cl6 = "Thunderbird" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}