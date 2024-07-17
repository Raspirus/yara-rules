rule SIGNATURE_BASE_HKTL_NET_NAME_Runascs : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "c5fc5b01-1d30-5af5-be99-e629cb23295b"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/antonioCoco/RunasCs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L537-L550"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9fd22a3e92222134c101693b944a2ad53055f9cfafe99823fd6f412981f5afa3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "RunasCs" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}