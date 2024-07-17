rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcliphistory : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "89ca4717-a4ec-5371-8dc3-bdb9933384af"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/FSecureLABS/SharpClipHistory"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2581-L2595"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5c88179f7b32cc4300f7ed85472247f91d812e523d07f4a11dc4e4b34344be1d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1126d5b4-efc7-4b33-a594-b963f107fe82" ascii wide
		$typelibguid0up = "1126D5B4-EFC7-4B33-A594-B963F107FE82" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}