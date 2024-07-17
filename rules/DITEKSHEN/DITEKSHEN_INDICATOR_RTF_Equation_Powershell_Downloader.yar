
rule DITEKSHEN_INDICATOR_RTF_Equation_Powershell_Downloader : FILE
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and PowerShell. Common exploit + dropper behavior."
		author = "ditekSHen"
		id = "5d1d65ef-e183-5a0d-a0fa-d0d5f09f21a1"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L453-L476"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "0b8b9b7b40f8b4d659de9e025a65d5c6b64c6066bb618a3e7ed3c318f70befe5"
		score = 75
		quality = 75
		tags = "FILE"
		snort2_sid = "910004-910005"
		snort3_sid = "910002"
		clamav_sig = "INDICATOR.RTF.EquationPowerShellDownloader"

	strings:
		$eq = "0200000002CE020000000000C000000000000046" ascii nocase
		$ps = "706f7765727368656c6c" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (($ps and $eq) and 1 of ($obj*))
}