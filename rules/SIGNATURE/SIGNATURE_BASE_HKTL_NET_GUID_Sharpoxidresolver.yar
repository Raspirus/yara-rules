rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpoxidresolver : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e8a957bc-3319-51c2-8289-01bd0b8a632a"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpOxidResolver"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5464-L5478"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "809ee7d9063700dbea2d33d01e4fb6b58ca9360fb6705f05eadb78fa0a2b2fb2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ce59f8ff-0ecf-41e9-a1fd-1776ca0b703d" ascii wide
		$typelibguid0up = "CE59F8FF-0ECF-41E9-A1FD-1776CA0B703D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}