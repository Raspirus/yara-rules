rule SIGNATURE_BASE_HKTL_NET_GUID_Koh : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9702526c-b10d-553d-a803-47e352533858"
		date = "2023-03-18"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/Koh"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5134-L5148"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b9cf1abdf4320a08f9c134e55a8f8531ef965785461b8f49687214810a143929"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii wide
		$typelibguid0up = "4D5350C8-7F8C-47CF-8CDE-C752018AF17E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}