import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Securityxploded_Ftppassworddumper : FILE
{
	meta:
		description = "Detects SecurityXploded FTP Password Dumper tool"
		author = "ditekSHen"
		id = "d876c201-b527-531c-9563-0b1a1c6334cb"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L739-L750"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "941bfb9b1ce71252c5aa05bd654bdcf1af6cc1d5f720bc2c239e17454f15beda"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "\\projects\\windows\\FTPPasswordDump\\Release\\FireMaster.pdb" ascii
		$s2 = "//Dump all the FTP passwords to a file \"c:\\passlist.txt\"" ascii
		$s3 = "//Dump all the FTP passwords to console" ascii
		$s4 = "FTP Password Dump" fullword wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}