rule SIGNATURE_BASE_HKTL_NET_GUID_Shellgen : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "538a4f12-5020-5c76-9208-363f435ed9a9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/jasondrawdy/ShellGen"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2141-L2155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ed7204d27cae6e0bcbe42247775e5eb20a968c5816f71135c7e2c92cc7fdffc5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii wide
		$typelibguid0up = "C6894882-D29D-4AE1-AEB7-7D0A9B915013" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}