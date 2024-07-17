rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpfruit : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "bf318530-b17d-5275-84b2-c284528bdae6"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rvrsh3ll/SharpFruit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2853-L2867"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3fffebded16430beae82315532548a4c035f4c9e92a893f441b1d5049d97f73a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii wide
		$typelibguid0up = "3DA2F6DE-75BE-4C9D-8070-08DA45E79761" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}