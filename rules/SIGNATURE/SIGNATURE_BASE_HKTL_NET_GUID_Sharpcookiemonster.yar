import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcookiemonster : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "87be6949-f4f5-5a5a-b804-c627ed0f4355"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/m0rv4i/SharpCookieMonster"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3553-L3567"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a4003459096d8bfdcb4c4761d32bdccfa273c3950f90c7605d555713cd215709"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii wide
		$typelibguid0up = "566C5556-1204-4DB9-9DC8-A24091BAAA8E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}