rule SIGNATURE_BASE_HKTL_NET_GUID_Sharphandler : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b71198a9-4d00-5d75-bc36-7c40655c84a3"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/jfmaes/SharpHandler"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4913-L4929"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "70e8c495c8a340e0afaa38faf0eb96101854a4dc51c29c571d9b74751aec91fd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii wide
		$typelibguid0up = "46E39AED-0CFF-47C6-8A63-6826F147D7BD" ascii wide
		$typelibguid1lo = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii wide
		$typelibguid1up = "11DC83C6-8186-4887-B228-9DC4FD281A23" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}