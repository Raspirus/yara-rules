rule DITEKSHEN_INDICATOR_TOOL_PET_Sharpstrike : FILE
{
	meta:
		description = "Detect SharpStrike post-exploitation tool written in C# that uses either CIM or WMI to query remote systems"
		author = "ditekSHen"
		id = "00b36fce-3d84-51cf-a800-042d7484d78c"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1145-L1160"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c479d85878d9f9659fc157f0c6706703af3748a8740df6a5090cddc720dd7661"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "SharpStrike v" wide
		$x2 = "[*] Agent is busy" wide
		$x3 = "SharpStrike_Fody" fullword ascii
		$s1 = "ServiceLayer.CIM" fullword ascii
		$s2 = "Models.CIM" fullword ascii
		$s3 = "<HandleCommand>b__" ascii
		$s4 = "MemoryStream" fullword ascii
		$s5 = "GetCommands" fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or all of ($s*))
}