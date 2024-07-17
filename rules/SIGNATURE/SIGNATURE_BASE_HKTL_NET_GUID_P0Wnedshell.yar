rule SIGNATURE_BASE_HKTL_NET_GUID_P0Wnedshell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "390b94d1-dda9-5a85-80ae-c79a3f7b0b9d"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3569-L3583"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bed8f4ea30218c137a26da5059934fa93316f4a3623284c5cb3a44b8bfacf7c4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2e9b1462-f47c-48ca-9d85-004493892381" ascii wide
		$typelibguid0up = "2E9B1462-F47C-48CA-9D85-004493892381" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}