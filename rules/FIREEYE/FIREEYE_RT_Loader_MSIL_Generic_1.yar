
rule FIREEYE_RT_Loader_MSIL_Generic_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "f919e3fc-cf76-53af-8f04-24921830666f"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/supplemental/yara/Loader_MSIL_Generic_1.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "b8415b4056c10c15da5bba4826a44ffd"
		logic_hash = "06cddd7e1c1c778348539cfd50f01d55f86689dec86c045d7ce7b9cd71690e07"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 5

	strings:
		$MSIL = "_CorExeMain"
		$opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
		$str1 = "DllImportAttribute"
		$str2 = "FromBase64String"
		$str3 = "ResumeThread"
		$str4 = "OpenThread"
		$str5 = "SuspendThread"
		$str6 = "QueueUserAPC"

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and $MSIL and all of them
}