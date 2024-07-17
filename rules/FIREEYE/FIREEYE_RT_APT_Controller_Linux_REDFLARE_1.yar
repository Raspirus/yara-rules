
rule FIREEYE_RT_APT_Controller_Linux_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "79a69740-7209-5c56-ad6f-eb4d0b29beaf"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Controller_Linux_REDFLARE_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		logic_hash = "d6b0cc5f386da9bff8a8293f2b3857406044ab42f7c1bb23d5096052a3c42ce4"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "/RedFlare/gorat_server"
		$2 = "RedFlare/sandals"
		$3 = "goratsvr.CommandResponse" fullword
		$4 = "goratsvr.CommandRequest" fullword

	condition:
		( uint32(0)==0x464c457f) and all of them
}