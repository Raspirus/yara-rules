import "pe"


rule DITEKSHEN_INDICATOR_TOOL_HFS_Webserver : FILE
{
	meta:
		description = "Detects HFS Web Server"
		author = "ditekSHen"
		id = "2c9d9a38-8a6c-5c53-84bc-4eef77933172"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L647-L658"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f5b8947e3858466dae5f476790842500f8184c4676d8c0c4870adb7fd3206652"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "SOFTWARE\\Borland\\Delphi\\" ascii
		$s2 = "C:\\code\\mine\\hfs\\scriptLib.pas" fullword ascii
		$s3 = "hfs.*;*.htm*;descript.ion;*.comment;*.md5;*.corrupted;*.lnk" ascii
		$s4 = "Server: HFS" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}