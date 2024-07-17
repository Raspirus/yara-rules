rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcat : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "450d13c6-93ae-5bf5-bdde-d874ab6c0cd5"
		date = "2023-11-30"
		modified = "2024-04-24"
		reference = "https://github.com/theart42/Sharpcat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5480-L5492"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "143757610d66c5d7bbba96ef810d518f38ad8ea0e924be23aa59e8c514154fe0"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "d16fd95f-23ce-4f8d-8763-b9f5a9cdd0c3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}