
rule FIREEYE_RT_Trojan_Raw_Generic_4 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "9092f9bb-cab6-55c0-9452-70a6407db93a"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/BEACON/supplemental/yara/Trojan_Raw_Generic_4.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "f41074be5b423afb02a74bc74222e35d"
		logic_hash = "8ffd23631c1a9d1abe6695858ec34d61261b3b3f097be94372f3f34e46e7211e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
		$s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }

	condition:
		uint16(0)!=0x5A4D and all of them
}