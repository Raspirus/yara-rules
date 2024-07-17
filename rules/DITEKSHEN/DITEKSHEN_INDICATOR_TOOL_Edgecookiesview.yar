rule DITEKSHEN_INDICATOR_TOOL_Edgecookiesview : FILE
{
	meta:
		description = "Detects EdgeCookiesView"
		author = "ditekSHen"
		id = "42c6eb2e-bf5c-5956-9009-c29551ce715d"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L833-L847"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9ba6d416e02c1958806356c67636609dcca758da9f7e3d1fc15244cc5ff038fc"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "AddRemarkCookiesTXT" fullword wide
		$s2 = "# Netscape HTTP Cookie File" fullword wide
		$s3 = "/scookiestxt" fullword wide
		$s4 = "/deleteregkey" fullword wide
		$s5 = "Load cookies from:" wide
		$s6 = "Old cookies folder of Edge/IE" wide
		$pdb = "\\EdgeCookiesView\\Release\\EdgeCookiesView.pdb" ascii

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or (($pdb) and 2 of ($s*)))
}