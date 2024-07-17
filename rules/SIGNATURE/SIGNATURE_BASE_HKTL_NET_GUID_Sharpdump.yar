rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpdump : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b613092f-9006-5405-b07e-59737410ac1e"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/SharpDump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1168-L1182"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "65e28a356cc975a3014f59551035a324d21039e39a8596b5980ad0c0e4d0a811"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii wide
		$typelibguid0up = "79C9BBA3-A0EA-431C-866C-77004802D8A0" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}