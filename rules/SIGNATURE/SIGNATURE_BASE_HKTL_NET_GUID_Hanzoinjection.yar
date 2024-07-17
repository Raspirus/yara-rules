import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Hanzoinjection : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c432bf68-49bf-57c7-bbfa-7bd2f3506c52"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/P0cL4bs/hanzoInjection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1252-L1266"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aec8befc497505ea750ce0cfc1e0b1ef21b5a6b97660f5403d6612629edaa114"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii wide
		$typelibguid0up = "32E22E25-B033-4D98-A0B3-3D2C3850F06C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}