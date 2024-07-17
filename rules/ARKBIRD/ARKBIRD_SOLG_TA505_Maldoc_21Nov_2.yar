rule ARKBIRD_SOLG_TA505_Maldoc_21Nov_2 : FILE
{
	meta:
		description = "invitation (1).xls"
		author = "Arkbird_SOLG"
		id = "e6328342-0d08-58a3-befe-15de41649763"
		date = "2019-11-21"
		modified = "2019-11-21"
		reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/20-11-19/Yara_Rule_TA505_Nov19.yar#L85-L116"
		license_url = "N/A"
		logic_hash = "84c7f064fb813934e397d81dad8af6288cb919e046cd2bb16f9ca6dc348c43c2"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "270b398b697f10b66828afe8d4f6489a8de48b04a52a029572412ae4d20ff89b"

	strings:
		$x1 = "C:\\Users\\J\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\AFFA0BDC.tmp" fullword wide
		$x2 = "C:\\Users\\J\\AppData\\Local\\Temp\\AFFA0BDC.tmp" fullword wide
		$x3 = "C:\\Windows\\system32\\FM20.DLL" fullword ascii
		$x4 = "C:\\Users\\J\\AppData\\Local\\Temp\\VBE\\MSForms.exd" fullword ascii
		$x5 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
		$x6 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
		$x7 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
		$x8 = "*\\G{BA45F137-16B2-487D-9A21-F38179C0576C}#2.0#0#C:\\Users\\J\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms 2.0 Object" wide
		$s9 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
		$s10 = "lIySgefa86jIfdEkSZVDoSs5BDkcalCieNBN4EqfVaEs2wWD4OjpTiOBqDrL3d9WCaDAKZpoJPRnoacfQPhucmy69axznNmRbRY12v3ez5PdAAnpAl5m5NUqKHBKCYb5" ascii
		$s11 = "35mvkZ9ZvIttuHSTUKWZCdOsh5j4Y1p2pJ3vi5onOXnMcEPIUIK1UWAYq3noPeaDtAdUOxKYvIlNZbqMpJjqpxhCidfpQ9GJXStKA44w7UFlKV9oMK8f5Tn6tKMKsviw" ascii
		$s12 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
		$s13 = "verkar.dll" fullword ascii
		$s14 = "intc.dll" fullword ascii
		$s15 = "YjAygups4wPzNU7lNIGBuFbv6Triw8rxEPLSjrYSKXdUV8QuzbwJvdHshfBvdh66er47iobvTX1FCqI8d6RuKRcBhsLdYCOC1hPEdTllabYHlcZ1FDsgyLuwoCZYM7Fq" ascii
		$s16 = "MinuetsOs.dll" fullword wide
		$s17 = "KaBYL8xLRpN7VMzibXEzxh2GetwfB6MY9k3dRCNncC5eiyKNTaTrcoUDi4TrLrkULX7KSvAHjrw4lXxPRSvBmvWUzz5WRwKTskBtBa4xIlhT1ZruGeI36SIqamksANYW" ascii
		$s18 = "XmhvJDfd16Hxk6eRMKJ7sqYIVneFVN7iUzRF8or7LKNKW9bhf5a7V5OGwIIvyJrm8yMUoITytLvRMoVWm7z1NawYTkjzP5HbtBLxwp3GkLMjJ74iWVjBjzI8cWadyuRy" ascii
		$s19 = "Sx3mdokmfv27AYhtFublOb5Exec1r1b5LAAbsRHrjLKTWiG4K9dKXbuQBxY9mt4nu7u9ygaWWTcczlRpGhpsXzgKgTI52IfZRxyZWHFD8pXd9sqqOJBedLy4ZT3OHe5n" ascii
		$s20 = "C:\\Windows\\system32\\stdole2.tlb" fullword ascii

	condition:
		uint16(0)==0xcfd0 and filesize <5000KB and 1 of ($x*) and 4 of them
}