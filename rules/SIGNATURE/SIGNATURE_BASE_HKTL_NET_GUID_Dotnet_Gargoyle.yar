rule SIGNATURE_BASE_HKTL_NET_GUID_Dotnet_Gargoyle : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5efd0c83-cb65-5bda-b55e-4a89db5f337c"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/countercept/dotnet-gargoyle"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1793-L1811"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "29147b4e14f45757274ca1bc0d140323a908d663f580b00cc705bd9cf3072f56"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "76435f79-f8af-4d74-8df5-d598a551b895" ascii wide
		$typelibguid0up = "76435F79-F8AF-4D74-8DF5-D598A551B895" ascii wide
		$typelibguid1lo = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii wide
		$typelibguid1up = "5A3FC840-5432-4925-B5BC-ABC536429CB5" ascii wide
		$typelibguid2lo = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii wide
		$typelibguid2up = "6F0BBB2A-E200-4D76-B8FA-F93C801AC220" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}