rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsvc : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cbc1d7d4-f3b4-5d02-84ae-621398cb7b51"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/jnqpblc/SharpSvc"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4795-L4809"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "61a4269200c699c5d00bde40e11cfec92da5cf7c7aeaffaedf60e70bcb31ccdf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii wide
		$typelibguid0up = "52856B03-5ACD-45E0-828E-13CCB16942D1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}