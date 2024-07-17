
rule FIREEYE_RT_Hacktool_MSIL_Sharpivot_3 : FILE
{
	meta:
		description = "This rule looks for .NET PE files that have the strings of various method names in the SharPivot code."
		author = "FireEye"
		id = "616333fc-4075-5f04-823a-1164717a2b87"
		date = "2020-12-10"
		modified = "2020-12-10"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPIVOT/production/yara/HackTool_MSIL_SharPivot_3.yar#L4-L31"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e4efa759d425e2f26fbc29943a30f5bd"
		logic_hash = "ecf13e47e409efd68b508735a84be6a1627f5b0c0cea6b90434fc9ba5b1d8cf5"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$msil = "_CorExeMain" ascii wide
		$str1 = "SharPivot" ascii wide
		$str2 = "ParseArgs" ascii wide
		$str3 = "GenRandomString" ascii wide
		$str4 = "ScheduledTaskExists" ascii wide
		$str5 = "ServiceExists" ascii wide
		$str6 = "lpPassword" ascii wide
		$str7 = "execute" ascii wide
		$str8 = "WinRM" ascii wide
		$str9 = "SchtaskMod" ascii wide
		$str10 = "PoisonHandler" ascii wide
		$str11 = "SCShell" ascii wide
		$str12 = "SchtaskMod" ascii wide
		$str13 = "ServiceHijack" ascii wide
		$str14 = "commandArg" ascii wide
		$str15 = "payloadPath" ascii wide
		$str16 = "Schtask" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $msil and all of ($str*)
}