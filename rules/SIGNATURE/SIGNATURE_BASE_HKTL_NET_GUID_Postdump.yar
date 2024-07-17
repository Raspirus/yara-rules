rule SIGNATURE_BASE_HKTL_NET_GUID_Postdump : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "7f33e76c-0227-5c23-b821-c5c9753e2384"
		date = "2023-12-19"
		modified = "2024-04-24"
		reference = "https://github.com/YOLOP0wn/POSTDump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5565-L5577"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e5bbef2fe7122855d7e5300ebf78631149e60b08793a4a21a4ac8b337f4bee60"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "e54195f0-060c-4b24-98f2-ad9fb5351045" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}