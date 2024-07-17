
rule FIREEYE_RT_APT_Loader_Raw32_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "8f8ec27f-afac-5da5-b76f-b984e14e0066"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Raw32_REDFLARE_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4022baddfda3858a57c9cbb0d49f6f86"
		logic_hash = "05ed89bd82600b4d5ef01ece2e0a9bd84e968988fd2bda1bab4ec316a9a9906b"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }

	condition:
		( uint16(0)!=0x5A4D) and all of them
}