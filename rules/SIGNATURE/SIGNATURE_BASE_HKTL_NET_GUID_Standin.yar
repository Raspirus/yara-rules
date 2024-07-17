rule SIGNATURE_BASE_HKTL_NET_GUID_Standin : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2af3c28a-ce5d-5dea-9abe-ff54b180049e"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/FuzzySecurity/StandIn"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2733-L2747"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "105be83eb5db667b9f27f2a514e0d04748ca006ef64aa01b9f643c227e7f1639"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii wide
		$typelibguid0up = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}