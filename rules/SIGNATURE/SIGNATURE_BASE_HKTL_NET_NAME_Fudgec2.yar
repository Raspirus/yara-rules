rule SIGNATURE_BASE_HKTL_NET_NAME_Fudgec2 : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "a8e70bce-76dd-53dc-9a19-1cc6795fdef3"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/Ziconius/FudgeC2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L462-L475"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "89f3bf4b81a901e813c3021422c362d7e075dec7fd76240be121f677039f1994"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "FudgeC2" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}