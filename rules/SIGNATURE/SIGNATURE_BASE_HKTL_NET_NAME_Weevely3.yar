
rule SIGNATURE_BASE_HKTL_NET_NAME_Weevely3 : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "6bf766b6-d065-5a84-8258-3be448b9cbb8"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/epinna/weevely3"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L447-L460"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c57c6ba5276679a2d32e9b0ebb61059c5bed1ba45f9792ecef3d5c7244f38f24"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "weevely3" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}