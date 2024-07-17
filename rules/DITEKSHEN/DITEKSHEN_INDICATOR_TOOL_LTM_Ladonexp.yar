import "pe"


rule DITEKSHEN_INDICATOR_TOOL_LTM_Ladonexp : FILE
{
	meta:
		description = "Detect Ladon tool that assists in lateral movement across a network"
		author = "ditekSHen"
		id = "bd1e7ef5-ae68-5e0d-8261-0eb765453bae"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1180-L1191"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "22f6a717b8464bddd850bb5ea8b416e99bceb91fe917f188be178f2fff620730"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "txt_cscandll.Text" fullword wide
		$s2 = "CscanWebExpBuild.frmMain.resources" fullword ascii
		$s3 = "= \"$HttpXforwardedFor$\";" ascii
		$s4 = "namespace netscan" fullword ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}