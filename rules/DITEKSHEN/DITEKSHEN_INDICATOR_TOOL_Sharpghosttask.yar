rule DITEKSHEN_INDICATOR_TOOL_Sharpghosttask : FILE
{
	meta:
		description = "Detects SharpGhostTask"
		author = "ditekSHen"
		id = "84d71179-0cfd-5389-b6bd-92c292361b3c"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1870-L1881"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "3de8d9fe7804e208ff556b6bedbd80eebfda1a730626403418a555ad9fbbb820"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "Ghosted" wide
		$x2 = /--target(binary|task)/ fullword wide
		$x3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\T" wide nocase
		$s4 = "__GhostTask|" ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}