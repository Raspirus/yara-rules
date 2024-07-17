rule SIGNATURE_BASE_HKTL_NET_GUID_Unmanagedpowershell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "49ff1362-0ac5-580d-97f3-516f2a10072b"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/leechristensen/UnmanagedPowerShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3757-L3771"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "26e59a31b1021c6e65711ee8d58cfdf3e1a8563b91f0f55722e1306854103ac6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii wide
		$typelibguid0up = "DFC4EEBB-7384-4DB5-9BAD-257203029BD9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}