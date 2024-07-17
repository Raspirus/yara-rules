
rule FIREEYE_RT_APT_Hacktool_MSIL_TITOSPECIAL_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b12490ba-41f6-5469-bcbb-0d2e0055c193"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TITOSPECIAL/production/yara/APT_HackTool_MSIL_TITOSPECIAL_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4bf96a7040a683bd34c618431e571e26"
		logic_hash = "6def0c667d38c1bad9233628e509bdcaed322e75be4ff3823b0f788c391e090c"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 5

	strings:
		$ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
		$ind_s1 = "NtReadVirtualMemory" fullword wide
		$ind_s2 = "WriteProcessMemory" fullword
		$shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
		$shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of ($ind*) and any of ($shellcode*)
}