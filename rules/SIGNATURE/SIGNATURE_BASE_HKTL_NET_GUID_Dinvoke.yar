rule SIGNATURE_BASE_HKTL_NET_GUID_Dinvoke : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f3b0ef47-a92c-5c5d-a9e2-09579fcb438e"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/TheWover/DInvoke"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4607-L4621"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3fac2563205327a173814141c035c8be78d43d8409db34954ac6027b3039d7c0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii wide
		$typelibguid0up = "B77FDAB5-207C-4CDB-B1AA-348505C54229" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}