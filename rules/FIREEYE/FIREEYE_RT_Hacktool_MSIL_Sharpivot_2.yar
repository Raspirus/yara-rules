rule FIREEYE_RT_Hacktool_MSIL_Sharpivot_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "8d6d28ce-de3a-5a38-b654-ba1372d47568"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPIVOT/production/yara/HackTool_MSIL_SharPivot_2.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e4efa759d425e2f26fbc29943a30f5bd"
		logic_hash = "14e4a29a32e8441a6f7f322e09cd9bb9822ae47eaa1fdf8e09c90998b03658f5"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s1 = "costura"
		$s2 = "cmd_schtask" wide
		$s3 = "cmd_wmi" wide
		$s4 = "cmd_rpc" wide
		$s5 = "GoogleUpdateTaskMachineUA" wide
		$s6 = "servicehijack" wide
		$s7 = "poisonhandler" wide

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}