
rule FIREEYE_RT_APT_Loader_Win_PGF_1 : FILE
{
	meta:
		description = "PDB string used in some PGF DLL samples"
		author = "FireEye"
		id = "14e2102c-3572-5314-999c-ff3f6c94de03"
		date = "2024-03-04"
		modified = "2024-03-04"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win_PGF_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "013c7708f1343d684e3571453261b586"
		logic_hash = "9dede268d33a38e980026917bd01bc47a72bfe60ba4a999c91eb727a2f377462"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 6

	strings:
		$pdb1 = /RSDS[\x00-\xFF]{20}c:\\source\\dllconfig-master\\dllsource[\x00-\xFF]{0,500}\.pdb\x00/ nocase
		$pdb2 = /RSDS[\x00-\xFF]{20}C:\\Users\\Developer\\Source[\x00-\xFF]{0,500}\\Release\\DllSource\.pdb\x00/ nocase
		$pdb3 = /RSDS[\x00-\xFF]{20}q:\\objchk_win7_amd64\\amd64\\init\.pdb\x00/ nocase

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and filesize <15MB and any of them
}