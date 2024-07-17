
rule FIREEYE_RT_Hacktool_MSIL_Sharpersist_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "49d7891e-b97a-52a8-acfd-bbf986732d6c"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPERSIST/production/yara/HackTool_MSIL_SharPersist_2.yar#L4-L23"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "98ecf58d48a3eae43899b45cec0fc6b7"
		logic_hash = "57387352f8fd08e8b859dffc1164d46370f248b337526c265634160010572a00"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$a1 = "SharPersist.lib"
		$a2 = "SharPersist.exe"
		$b1 = "ERROR: Invalid hotkey location option given." ascii wide
		$b2 = "ERROR: Invalid hotkey given." ascii wide
		$b3 = "ERROR: Keepass configuration file not found." ascii wide
		$b4 = "ERROR: Keepass configuration file was not found." ascii wide
		$b5 = "ERROR: That value already exists in:" ascii wide
		$b6 = "ERROR: Failed to delete hidden registry key." ascii wide
		$pdb1 = "\\SharPersist\\"
		$pdb2 = "\\SharPersist.pdb"

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and ((@pdb2[1]<@pdb1[1]+50) or (1 of ($a*) and 2 of ($b*)))
}