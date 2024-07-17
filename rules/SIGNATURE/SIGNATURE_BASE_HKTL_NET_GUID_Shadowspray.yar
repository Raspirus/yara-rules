rule SIGNATURE_BASE_HKTL_NET_GUID_Shadowspray : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "91dd52ef-07a1-5ffd-b5c3-59bca18d4c7c"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/Dec0ne/ShadowSpray"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5416-L5430"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1d5992f9f58b6f7254fd8436aa32c6744d7a7ac3c70d94b3d7325c7a4c720475"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7e47d586-ddc6-4382-848c-5cf0798084e1" ascii wide
		$typelibguid0up = "7E47D586-DDC6-4382-848C-5CF0798084E1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}