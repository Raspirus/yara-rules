rule SIGNATURE_BASE_HKTL_NET_GUID_Ysoserial_Net : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "80483cd4-76e6-5629-bed7-4ae2e455222c"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/pwntester/ysoserial.net"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3951-L3967"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e423b73cd2dd2374a95ad0a36cd34d8d5b4d1085d708781857ea3893b31b22fb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii wide
		$typelibguid0up = "E1E8C029-F7CD-4BD1-952E-E819B41520F0" ascii wide
		$typelibguid1lo = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii wide
		$typelibguid1up = "6B40FDE7-14EA-4F57-8B7B-CC2EB4A25E6C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}