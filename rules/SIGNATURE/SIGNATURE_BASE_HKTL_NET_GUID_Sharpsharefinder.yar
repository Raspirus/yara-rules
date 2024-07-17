rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsharefinder : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "bb485347-ea9b-5f26-99ad-bedc38bfecd5"
		date = "2023-12-19"
		modified = "2024-04-24"
		reference = "https://github.com/mvelazc0/SharpShareFinder"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5550-L5562"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "72b2c6c9f4da68ba8e9656ff2d9da962f9d791f031c1d7fb74d74ddd17ba49de"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "64bfeb18-b65c-4a83-bde0-b54363b09b71" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}