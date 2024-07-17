rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpstat : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "649c6cc0-e43b-558c-9567-00f352af528b"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/Raikia/SharpStat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3101-L3115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8b9193262c5ab6e43d804c964821ab986c038a0ba834b22785e75e846fca649b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii wide
		$typelibguid0up = "FFC5C721-49C8-448D-8FF4-2E3A7B7CC383" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}