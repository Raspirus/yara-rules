import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PWS_Pwdump7 : FILE
{
	meta:
		description = "Detects Pwdump7 password Dumper"
		author = "ditekSHen"
		id = "dc6ff544-b9de-547b-9fa8-7d0b32e9592d"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L242-L254"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f84ab69ecc6837a826dc8726785165b8135edf51a47fb5bbaf19dc589b3032bd"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "savedump.dat" fullword ascii
		$s2 = "Asd -_- _RegEnumKey fail!" fullword ascii
		$s3 = "\\SAM\\" ascii
		$s4 = "Unable to dump file %S" fullword ascii
		$s5 = "NO PASSWORD" ascii

	condition:
		( uint16(0)==0x5a4d and 4 of them ) or ( all of them )
}