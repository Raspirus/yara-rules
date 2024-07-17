rule FIREEYE_RT_Credtheft_MSIL_Titospecial_1 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
		author = "FireEye"
		id = "932bb013-03de-5cf7-89e9-b3232151d303"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TITOSPECIAL/production/yara/CredTheft_MSIL_TitoSpecial_1.yar#L4-L27"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4bf96a7040a683bd34c618431e571e26"
		logic_hash = "4ac9a5ede4aea5d73545b459eb635f87ce08ba521afa48b76d2cfa94f1379226"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$str1 = "Minidump" ascii wide
		$str2 = "dumpType" ascii wide
		$str3 = "WriteProcessMemory" ascii wide
		$str4 = "bInheritHandle" ascii wide
		$str5 = "GetProcessById" ascii wide
		$str6 = "SafeHandle" ascii wide
		$str7 = "BeginInvoke" ascii wide
		$str8 = "EndInvoke" ascii wide
		$str9 = "ConsoleApplication1" ascii wide
		$str10 = "getOSInfo" ascii wide
		$str11 = "OpenProcess" ascii wide
		$str12 = "LoadLibrary" ascii wide
		$str13 = "GetProcAddress" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of ($str*)
}