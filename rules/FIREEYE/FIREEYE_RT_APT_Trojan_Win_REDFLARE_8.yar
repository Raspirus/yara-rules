rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_8 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b090df60-8f4e-51ca-944c-6f9ce2d9c913"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_8.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
		logic_hash = "5b8a0402886daebefb995e7df0877d51727c5b8dc58eeb8ff16ceec5e7811a20"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "PSRunner.PSRunner" fullword
		$2 = "CorBindToRuntime" fullword
		$3 = "ReportEventW" fullword
		$4 = "InvokePS" fullword wide
		$5 = "runCommand" fullword
		$6 = "initialize" fullword
		$trap = { 03 40 00 80 E8 [4] CC }

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}