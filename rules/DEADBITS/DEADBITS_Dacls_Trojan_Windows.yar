rule DEADBITS_Dacls_Trojan_Windows : FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "424b2c0d-2373-5a72-9a97-52b4bfc5cdcf"
		date = "2020-01-07"
		modified = "2020-01-07"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/Dacls_Windows.yara#L1-L30"
		license_url = "N/A"
		logic_hash = "b77df7e3be9c264d6a63d40dbf49c41e9dd55b4e570c063b5710b849c36cc166"
		score = 75
		quality = 80
		tags = "FILE"
		Author = "Adam M. Swanda"

	strings:
		$fext00 = ".exe" ascii wide
		$fext01 = ".cmd" ascii wide
		$fext02 = ".bat" ascii wide
		$fext03 = ".com" ascii wide
		$str00 = "Software\\mthjk" ascii wide
		$str01 = "WindowsNT.dll" ascii fullword
		$str02 = "GET %s HTTP/1.1" ascii fullword
		$str03 = "content-length:" ascii fullword
		$str04 = "Connection: keep-alive" ascii fullword
		$cls00 = "c_2910.cls" ascii fullword
		$cls01 = "k_3872.cls" ascii fullword

	condition:
		( uint16(0)==0x5a4d) and (( all of ($cls*)) or ( all of ($fext*) and all of ($str*)))
}