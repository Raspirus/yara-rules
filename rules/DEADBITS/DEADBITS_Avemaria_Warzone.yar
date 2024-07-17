rule DEADBITS_Avemaria_Warzone : AVEMARIA WARZONE WINMALWARE INFOSTEALER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "1e03927b-d59c-5e1f-bdee-e44dfb172fad"
		date = "2019-07-18"
		modified = "2019-08-08"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/avemaria_warzone.yara#L1-L32"
		license_url = "N/A"
		logic_hash = "1fe55fc8ea80616b11757193c2c74b9cf577ab661ddca4c6c64cfad63a300614"
		score = 75
		quality = 80
		tags = "AVEMARIA, WARZONE, WINMALWARE, INFOSTEALER, FILE"
		Author = "Adam M. Swanda"

	strings:
		$str1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
		$str2 = "MsgBox.exe" wide fullword
		$str4 = "\\System32\\cmd.exe" wide fullword
		$str6 = "Ave_Maria" wide
		$str7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii fullword
		$str8 = "SMTP Password" wide fullword
		$str11 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide fullword
		$str12 = "\\sqlmap.dll" wide fullword
		$str14 = "SELECT * FROM logins" ascii fullword
		$str16 = "Elevation:Administrator!new" wide
		$str17 = "/n:%temp%" ascii wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB) and (5 of ($str*) or all of them )
}