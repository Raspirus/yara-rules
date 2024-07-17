
rule SIGNATURE_BASE_HKTL_NET_NAME_Sharpoffensiveshell : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "f223fb95-9f16-5504-a6ce-de9d75b38eaa"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/darkr4y/SharpOffensiveShell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L687-L700"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "36bcae7817eed375e48822a49e6875295ea1037217231a7f9ae88a9b8af95530"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "SharpOffensiveShell" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}