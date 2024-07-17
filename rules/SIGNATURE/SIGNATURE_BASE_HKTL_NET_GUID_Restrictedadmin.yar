rule SIGNATURE_BASE_HKTL_NET_GUID_Restrictedadmin : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1b3572a5-bb21-58bb-91f9-963a0a17d699"
		date = "2023-03-18"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/RestrictedAdmin"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5182-L5196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fc8fe9df771fb794a2ea44d68741003451747a7eb10156a9ed486f87a2d42c6d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "79f11fc0-abff-4e1f-b07c-5d65653d8952" ascii wide
		$typelibguid0up = "79F11FC0-ABFF-4E1F-B07C-5D65653D8952" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}