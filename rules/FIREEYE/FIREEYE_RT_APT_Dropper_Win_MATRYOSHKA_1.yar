rule FIREEYE_RT_APT_Dropper_Win_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_dropper.rs"
		author = "FireEye"
		id = "7fd305c7-0b1b-5d91-b968-7f1fb0a8ae47"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Dropper_Win_MATRYOSHKA_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "edcd58ba5b1b87705e95089002312281"
		logic_hash = "a7bf7599ec9b4b1d09a8c90b70ae565a9396fb31d449da3c1492d6fa336d9c5e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "\x00matryoshka.exe\x00"
		$s2 = "\x00Unable to write data\x00"
		$s3 = "\x00Error while spawning process. NTStatus: \x0a\x00"
		$s4 = "\x00.execmdstart/Cfailed to execute process\x00"

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}