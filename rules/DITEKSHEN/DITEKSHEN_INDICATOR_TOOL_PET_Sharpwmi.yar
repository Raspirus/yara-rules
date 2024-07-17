import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PET_Sharpwmi : FILE
{
	meta:
		description = "Detects SharpWMI"
		author = "ditekSHen"
		id = "9c58d9fa-04b8-5a9c-8ae9-ff2e7530772f"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L604-L619"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "e6c5764d0883e2882e06f07e4729362011a4d65614259b85978e1c6ef5cfadb7"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$s1 = "scriptKillTimeout" fullword ascii
		$s2 = "RemoteWMIExecuteWithOutput" fullword ascii
		$s3 = "RemoteWMIFirewall" fullword ascii
		$s4 = "iex([char[]](@({0})|%{{$_-bxor{1}}}) -join '')" fullword wide
		$s5 = "\\\\{0}\\root\\subscription" fullword wide
		$s6 = "_Context##RANDOM##" fullword wide
		$s7 = "executevbs" fullword wide
		$s8 = "scriptb64" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}