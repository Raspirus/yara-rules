rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcloud : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "048b0239-ea13-58ff-af35-fd505b4c977a"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/chrismaddalena/SharpCloud"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5246-L5260"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d1ad4088ce5b4216930d74ab7c2bc7b4d700928740faff27ebbb69e79068b14e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ca4e257e-69c1-45c5-9375-ba7874371892" ascii wide
		$typelibguid0up = "CA4E257E-69C1-45C5-9375-BA7874371892" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}