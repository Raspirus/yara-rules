
rule SIGNATURE_BASE_HKTL_NET_NAME_Aggressiveproxy : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "e2d3c4e2-404b-59f8-b3d0-a7cef4dfd0ff"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/EncodeGroup/AggressiveProxy"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L402-L415"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "702b0cc858cb1687962ac403a730e5f778bf51fc91627c50103e4299f4a3ca5f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "AggressiveProxy" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}