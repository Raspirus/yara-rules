rule SIGNATURE_BASE_HKTL_NET_NAME_Gray_Hat_Csharp_Code : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "0a94cadc-cc7b-5817-8788-bb1e53937fad"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/brandonprry/gray_hat_csharp_code"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L627-L640"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4520528cd6b1832c97fa79442f9d448d54bad4e6944984fa6e71f34246259e28"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "gray_hat_csharp_code" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}