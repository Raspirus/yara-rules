
rule FIREEYE_RT_APT_Backdoor_Win_GORAT_1 : FILE
{
	meta:
		description = "This detects if a sample is less than 50KB and has a number of strings found in the Gorat shellcode (stage0 loader). The loader contains an embedded DLL (stage0.dll) that contains a number of unique strings. The 'Cookie' string found in this loader is important as this cookie is needed by the C2 server to download the Gorat implant (stage1 payload)."
		author = "FireEye"
		id = "5ac84cf1-49fb-533d-b211-b1a92239063b"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/APT_Backdoor_Win_GORAT_1.yar#L4-L23"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "66cdaa156e4d372cfa3dea0137850d20"
		logic_hash = "f6a0a923f64375e7ffdc080aec41db19a9e162405f1290ed0bbcce5a342bdadb"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$s1 = "httpComms.dll" ascii wide
		$s2 = "Cookie: SID1=%s" ascii wide
		$s3 = "Global\\" ascii wide
		$s4 = "stage0.dll" ascii wide
		$s5 = "runCommand" ascii wide
		$s6 = "getData" ascii wide
		$s7 = "initialize" ascii wide
		$s8 = "Windows NT %d.%d;" ascii wide
		$s9 = "!This program cannot be run in DOS mode." ascii wide

	condition:
		filesize <50KB and all of them
}