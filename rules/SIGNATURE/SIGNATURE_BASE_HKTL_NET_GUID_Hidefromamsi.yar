rule SIGNATURE_BASE_HKTL_NET_GUID_Hidefromamsi : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0fa1ce82-b662-5e18-a5da-8359c96cd6e9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1326-L1340"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c4c06b8f40a38d5386cb49befd7705552b471e443188b6af1d85d7bd4277cc1c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii wide
		$typelibguid0up = "B91D2D44-794C-49B8-8A75-2FBEC3FE3FE3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}