rule ARKBIRD_SOLG_TA505_Bin_21Nov_2 : FILE
{
	meta:
		description = "vspub1.bin"
		author = "Arkbird_SOLG"
		id = "2bbd1d3a-50ab-5c6a-97fe-60b5a86e8d18"
		date = "2019-11-21"
		modified = "2019-11-21"
		reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/20-11-19/Yara_Rule_TA505_Nov19.yar#L32-L50"
		license_url = "N/A"
		logic_hash = "43fb83abdeb1a31da836b4cf99dcda269f6d005cbb8eb2d845498d2c589574e1"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "54cc27076793d5de064813c61d52452d42f774d24b3859a63002d842914fd9cd"

	strings:
		$s1 = "glColor.dll" fullword ascii
		$s2 = "{sysdir}\\nvu*.exe" fullword ascii
		$s3 = "KLSUIrhekheirguhemure" fullword ascii
		$s4 = "tEo>qM" fullword ascii
		$s5 = "?\"?0?8?>?I?V?^?l?q?v?{?" fullword ascii
		$s6 = ";\";0;d;" fullword ascii
		$s7 = "T0p0v0|0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (pe.imphash()=="ff6dd5f31dd7c538ebc02542f09f4280" and pe.exports("setColor") or all of them )
}