import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Driver_Template : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "539f88c5-e779-55e0-98df-299a9068de9b"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/FuzzySecurity/Driver-Template"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4931-L4945"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "533cefcc86ff8eff8757041df8acf2a9c484d265b6aa9516c12adb606d6f71cb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii wide
		$typelibguid0up = "BDB79AD6-639F-4DC2-8B8A-CD9107DA3D69" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}