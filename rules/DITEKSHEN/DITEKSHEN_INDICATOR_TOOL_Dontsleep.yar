import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Dontsleep : FILE
{
	meta:
		description = "Detects Keep Host Unlocked (Don't Sleep)"
		author = "ditekShen"
		id = "f71bd0d5-a526-5f1e-8bd3-9e653db610a7"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1340-L1354"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b8e2132d3b36c3e2d2662a586916c7e4fc029f81af08b5c18006833c4e6f772f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = ":Repeat###DEL \"%s\"###if exist \"%s\" goto Repeat###DEL \"%s\"###" wide
		$s2 = "powrprof.dll,SetSuspendState" wide
		$s3 = "_selfdestruct.bat" wide
		$s4 = "please_sleep_block_" ascii
		$s5 = "Browser-Type: MiniBowserOK" wide
		$s6 = "m_use_all_rule_no_sleep" ascii
		$s7 = "BlockbyExecutionState: %d on:%d by_enable:%d" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}