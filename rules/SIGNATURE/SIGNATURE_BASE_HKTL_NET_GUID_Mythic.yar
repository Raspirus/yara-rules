rule SIGNATURE_BASE_HKTL_NET_GUID_Mythic : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "44237fac-1526-5587-83a1-61d7a54f7da9"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/its-a-feature/Mythic"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4164-L4180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f75bb7695d0de67f562e1c1d7505e0f13e9192ccd7bf6f2128897f4a871430be"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii wide
		$typelibguid0up = "91F7A9DA-F045-4239-A1E9-487FFDD65986" ascii wide
		$typelibguid1lo = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii wide
		$typelibguid1up = "0405205C-C2A0-4F9A-A221-48B5C70DF3B6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}