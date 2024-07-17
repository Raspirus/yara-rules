
rule FIREEYE_RT_APT_Loader_Raw64_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "8e937f6a-404f-53bd-9de2-ed63b1cf48b2"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Raw64_REDFLARE_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "5e14f77f85fd9a5be46e7f04b8a144f5"
		logic_hash = "dac122ccece8a6dd35a5fe9d37860a612aa50ab469b79f4375dbe776f60c7b57"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }

	condition:
		( uint16(0)!=0x5A4D) and all of them
}