import "pe"


rule DITEKSHEN_INDICATOR_TOOL_SCR_Amady : FILE
{
	meta:
		description = "Detects screenshot stealer DLL. Dropped by Amadey"
		author = "ditekSHen"
		id = "f7660899-ed12-5765-a856-6a1c7bbd8978"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L308-L320"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9e7ab39976e3219f0c6c3ce5341442343cc4baf30757cd1c9d0c2d3845fdda2f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "User-Agent: Uploador" fullword ascii
		$s2 = "Content-Disposition: form-data; name=\"data\"; filename=\"" fullword ascii
		$s3 = "WebUpload" fullword ascii
		$s4 = "Cannot assign a %s to a %s%List does not allow duplicates ($0%x)%String" wide
		$s5 = "scr.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 4 of them
}