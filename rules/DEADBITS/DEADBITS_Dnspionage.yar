
rule DEADBITS_Dnspionage : APT DNSCHANGER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "9f740645-60dc-5376-94ad-59d8efbf1942"
		date = "2019-07-18"
		modified = "2019-07-19"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/DNSpionage.yara#L1-L47"
		license_url = "N/A"
		logic_hash = "f20c71d0698d98cc58fa199c708ec7bf5cb0ec62503a20b532e752dab9aab920"
		score = 75
		quality = 78
		tags = "APT, DNSCHANGER, FILE"
		Description = "Attempts to detect DNSpionage PE samples"
		Author = "Adam M. Swanda"

	strings:
		$x00 = "/Loginnn?id=" fullword ascii
		$hdr0 = "Content-Disposition: fo" fullword ascii
		$hdr1 = "Content-Type: multi" fullword ascii
		$ua0 = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36" fullword ascii
		$ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" fullword ascii
		$str0 = "send command result error! status code is: " fullword ascii
		$str1 = "uploading command result form" fullword ascii
		$str2 = "log.txt" fullword ascii
		$str3 = "http host not found in config!" fullword ascii
		$str4 = "send command result" fullword ascii
		$str5 = "download error. status code: " fullword ascii
		$str6 = "get command with dns" fullword ascii
		$str7 = "dns host not found in config!" fullword ascii
		$str8 = "command result is: " fullword ascii
		$str9 = "command result size: " fullword ascii
		$str10 = "connection type not found in config!" fullword ascii
		$str11 = "commands: " fullword ascii
		$str12 = "command is: " fullword ascii
		$str13 = "port not found in config!" fullword ascii
		$str14 = "download filename not found! " fullword ascii
		$str15 = "base64 key not found in config!" fullword ascii
		$str16 = "download filename is: " fullword ascii
		$str17 = "config json is not valid" fullword ascii
		$str18 = "config file will be changed from server!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and ((5 of ($str*)) or ($x00 and (1 of ($hdr*)) and 1 of ($ua*)))
}