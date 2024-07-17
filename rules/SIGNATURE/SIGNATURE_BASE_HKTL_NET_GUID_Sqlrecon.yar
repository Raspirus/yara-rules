rule SIGNATURE_BASE_HKTL_NET_GUID_Sqlrecon : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f9ea5283-0a5c-5bde-966c-80869ee25888"
		date = "2023-01-20"
		modified = "2023-04-06"
		reference = "https://github.com/skahwah/SQLRecon"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5031-L5045"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fed5ef9d4702c463fd2f138f5e4cc0a1841fc329a2923afeca83f193bb6213ea"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "612c7c82-d501-417a-b8db-73204fdfda06" ascii wide
		$typelibguid0up = "612C7C82-D501-417A-B8DB-73204FDFDA06" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}