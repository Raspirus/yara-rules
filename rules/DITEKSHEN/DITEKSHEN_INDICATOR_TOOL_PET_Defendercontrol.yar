rule DITEKSHEN_INDICATOR_TOOL_PET_Defendercontrol : FILE
{
	meta:
		description = "Detects Defender Control"
		author = "ditekSHen"
		id = "7bc1f26e-2432-5642-b1e7-c87683f7d932"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L621-L631"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "826ed0643a07580750eb11c4cf2c2759f53b6c2bda51705476edc4808abccbf8"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Windows Defender Control" wide
		$s2 = "www.sordum.org" wide ascii
		$s3 = "dControl" wide

	condition:
		uint16(0)==0x5a4d and 2 of them
}