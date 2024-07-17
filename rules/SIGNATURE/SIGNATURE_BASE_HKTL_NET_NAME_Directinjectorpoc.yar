rule SIGNATURE_BASE_HKTL_NET_NAME_Directinjectorpoc : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "d9a430d7-b062-554b-aff4-cfd98d91e9fe"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/badBounty/directInjectorPOC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L92-L105"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ffdc5694668af6c82b493403373d2e2e915e45bca8d58ec1ab41c5a8bd28d781"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "directInjectorPOC" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}