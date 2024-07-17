
rule DITEKSHEN_INDICATOR_RTF_Equation_Bitsadmin_Downloader : FILE
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and BITSAdmin. Common exploit + dropper behavior."
		author = "ditekSHen"
		id = "e96a6f18-9a5e-58ca-829e-c82b444ad403"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L403-L426"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "39a07a0af243e929a6b3df48b6cf8a9d30bc8ef9e7deac494348945427b015e7"
		score = 75
		quality = 75
		tags = "FILE"
		snort2_sid = "910002-910003"
		snort3_sid = "910001"
		clamav_sig = "INDICATOR.RTF.EquationBITSAdminDownloader"

	strings:
		$eq = "0200000002CE020000000000C000000000000046" ascii nocase
		$ba = "6269747361646d696e" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (($eq and $ba) and 1 of ($obj*))
}