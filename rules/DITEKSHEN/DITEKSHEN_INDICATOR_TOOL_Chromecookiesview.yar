rule DITEKSHEN_INDICATOR_TOOL_Chromecookiesview : FILE
{
	meta:
		description = "Detects ChromeCookiesView"
		author = "ditekSHen"
		id = "c1b89468-edf2-59d1-89b3-5822fa19d6ab"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L866-L880"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "81acd0978fc03525e7092ab51c681b61f9de0252066ce871298e2cd96b1d3024"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "AddRemarkCookiesTXT" fullword wide
		$s2 = "Decrypt cookies" wide
		$s3 = "/scookiestxt" fullword wide
		$s4 = "/deleteregkey" fullword wide
		$s5 = "Cookies.txt Format" wide
		$s6 = "# Netscape HTTP Cookie File" wide
		$pdb = "\\ChromeCookiesView\\Release\\ChromeCookiesView.pdb" ascii

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or (($pdb) and 2 of ($s*)))
}