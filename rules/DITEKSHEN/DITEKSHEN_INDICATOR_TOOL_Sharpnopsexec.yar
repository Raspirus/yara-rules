import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Sharpnopsexec : FILE
{
	meta:
		description = "Detects SharpNoPSExec"
		author = "ditekSHen"
		id = "10898364-6d77-5127-a16b-5fd3b1c652d5"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L849-L864"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "c1d76639e7b6464d302729b48bbcd810216132868035904bb9866e7b31ccfac2"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "|-> Service" wide
		$s2 = "authenticated as" wide
		$s3 = "ImpersonateLoggedOnUser failed. Error:{0}" wide
		$s4 = "uPayload" fullword ascii
		$s5 = "pcbBytesNeeded" fullword ascii
		$s6 = "SharpNoPSExec" ascii wide
		$pdb1 = "SharpNoPSExec\\obj\\Debug\\SharpNoPSExec.pdb" ascii
		$pdb2 = "SharpNoPSExec\\obj\\Release\\SharpNoPSExec.pdb" ascii

	condition:
		uint16(0)==0x5a4d and (4 of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}