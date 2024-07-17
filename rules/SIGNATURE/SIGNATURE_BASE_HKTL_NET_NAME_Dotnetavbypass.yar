rule SIGNATURE_BASE_HKTL_NET_NAME_Dotnetavbypass : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "918eba2b-150d-5e69-bed0-0979ae889165"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/mandreko/DotNetAVBypass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L657-L670"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "574a5f1bc1873321042e932ddfd53853e8e06dff3b25f2ad41e6b8aaf150a8b2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "DotNetAVBypass" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}