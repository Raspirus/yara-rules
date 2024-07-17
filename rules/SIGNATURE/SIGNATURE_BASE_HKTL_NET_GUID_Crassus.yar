rule SIGNATURE_BASE_HKTL_NET_GUID_Crassus : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d4f94aa3-0431-5ac1-8718-0f0526c3714f"
		date = "2023-03-18"
		modified = "2023-04-06"
		reference = "https://github.com/vu-ls/Crassus"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5166-L5180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "27c2c67aed20f3d1ec2ef0393342e21a41590cc05c0361309054e0dc699d7cc9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7e9729aa-4cf2-4d0a-8183-7fb7ce7a5b1a" ascii wide
		$typelibguid0up = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}