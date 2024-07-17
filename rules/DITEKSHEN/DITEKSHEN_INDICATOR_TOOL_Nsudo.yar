import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Nsudo : FILE
{
	meta:
		description = "Detects NSudo allowing to run processes as TrustedInstaller or System"
		author = "ditekShen"
		id = "9a21b923-b02e-553b-8f53-026d7034c319"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1356-L1369"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "6bcffa79ca06b0b4178d6ea256f98d917c2b19cec0b059889b8d015d226a53f9"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "cmd /c start \"NSudo." wide
		$x2 = "*\\shell\\NSudo" fullword wide
		$x3 = "Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb" ascii
		$s1 = "-ShowWindowMode=Hide" wide
		$s2 = "?what@exception@@UEBAPEBDXZ" fullword ascii
		$s3 = "NSudo.RunAs." ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*) or 4 of them )
}