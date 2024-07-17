import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Pandora : FILE
{
	meta:
		description = "Detects Pandora tool to extract credentials from password managers"
		author = "ditekSHen"
		id = "3f71f24b-755f-5967-afbf-04a512bd0a19"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1741-L1755"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "dd5be3b99b62ec40c242225d9420b9ce299c4f348882b0380289309dfedbc1e8"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "process PID:" fullword wide
		$s2 = "Dump file created:" fullword wide
		$s3 = "System.Security.AccessControl.FileSystemAccessRule('Everyone', 'FullControl', 'Allow')" ascii
		$s4 = "{[math]::Round($_.PrivateMemorySize64" ascii
		$s5 = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $" ascii
		$s6 = "\"payload\":{\"logins\":" ascii
		$s7 = "\\pandora.pdb" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}