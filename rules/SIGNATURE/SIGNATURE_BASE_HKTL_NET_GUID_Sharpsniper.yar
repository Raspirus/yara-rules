import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsniper : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "14e6a3b8-5e1f-5dd8-9b51-22522ac317e7"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/HunnicCyber/SharpSniper"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4198-L4212"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5c2c67c24a8ad6ecfac03e9f5bad0731883503d974bf7a0ab313e31c30190fb5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii wide
		$typelibguid0up = "C8BB840C-04CE-4B60-A734-FAF15ABF7B18" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}