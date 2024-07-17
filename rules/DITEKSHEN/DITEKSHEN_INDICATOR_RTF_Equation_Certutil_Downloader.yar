
rule DITEKSHEN_INDICATOR_RTF_Equation_Certutil_Downloader : FILE
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and CertUtil. Common exploit + dropper behavior."
		author = "ditekSHen"
		id = "a47f31f9-91fc-5009-8aff-2b9e334c3139"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L428-L451"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "d6c62957ce40ed755a84bd9aa8900e4990c466097d6df55c539b289bf50fe94e"
		score = 75
		quality = 75
		tags = "FILE"
		snort2_sid = "910006-910007"
		snort3_sid = "910003"
		clamav_sig = "INDICATOR.RTF.EquationCertUtilDownloader"

	strings:
		$eq = "0200000002CE020000000000C000000000000046" ascii nocase
		$cu = "636572747574696c" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (($eq and $cu) and 1 of ($obj*))
}