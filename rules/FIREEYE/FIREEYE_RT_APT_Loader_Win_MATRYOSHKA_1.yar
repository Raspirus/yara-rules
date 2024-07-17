rule FIREEYE_RT_APT_Loader_Win_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_process_hollow.rs"
		author = "FireEye"
		id = "c07fb67e-ded5-593d-b5dc-d0e2c3b5a352"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Loader_Win_MATRYOSHKA_1.yar#L4-L24"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "44887551a47ae272d7873a354d24042d"
		logic_hash = "8f762684ffd3984630bf41ededa78b8993b53b22591a59912cabfe635775de53"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "ZwQueryInformationProcess" fullword
		$s2 = "WriteProcessMemory" fullword
		$s3 = "CreateProcessW" fullword
		$s4 = "WriteProcessMemory" fullword
		$s5 = "\x00Invalid NT Signature!\x00"
		$s6 = "\x00Error while creating and mapping section. NTStatus: "
		$s7 = "\x00Error no process information - NTSTATUS:"
		$s8 = "\x00Error while erasing pe header. NTStatus: "

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x020B) and all of them
}