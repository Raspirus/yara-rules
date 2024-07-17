rule FIREEYE_RT_APT_Hacktool_MSIL_WMISPY_2 : FILE
{
	meta:
		description = "wql searches"
		author = "FireEye"
		id = "474af878-a657-54bc-a063-04532df928d4"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WMISPY/production/yara/APT_HackTool_MSIL_WMISPY_2.yar#L4-L24"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "3651f252d53d2f46040652788499d65a"
		logic_hash = "553fc1e536482a56b3228a5c9ebac843af9083e8ac864bf65c81b36a39ca5e5e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$MSIL = "_CorExeMain"
		$str1 = "root\\cimv2" wide
		$str2 = "root\\standardcimv2" wide
		$str3 = "from MSFT_NetNeighbor" wide
		$str4 = "from Win32_NetworkLoginProfile" wide
		$str5 = "from Win32_IP4RouteTable" wide
		$str6 = "from Win32_DCOMApplication" wide
		$str7 = "from Win32_SystemDriver" wide
		$str8 = "from Win32_Share" wide
		$str9 = "from Win32_Process" wide

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and $MSIL and all of ($str*)
}