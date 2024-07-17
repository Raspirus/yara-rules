rule SIGNATURE_BASE_HKTL_NET_GUID_Antidebug : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f381081b-d0cb-593d-ad3d-28816f770b67"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/malcomvetter/AntiDebug"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3296-L3310"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "32ae8a5221f3b1c913163590291461fe7868f25be02c3b0b045a4934d97d244a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "997265c1-1342-4d44-aded-67964a32f859" ascii wide
		$typelibguid0up = "997265C1-1342-4D44-ADED-67964A32F859" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}