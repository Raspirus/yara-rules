rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpmapexec : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b4922734-a486-5c4d-9bd7-5146cfecbf01"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/cube0x0/SharpMapExec"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4262-L4276"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "49055d7159cf93e99b8e4ac53c29a66952955fa10457e7beca8e5e0277acec36"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii wide
		$typelibguid0up = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}