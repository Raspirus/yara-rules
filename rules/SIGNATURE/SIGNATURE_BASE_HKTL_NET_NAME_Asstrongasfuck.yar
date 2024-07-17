
rule SIGNATURE_BASE_HKTL_NET_NAME_Asstrongasfuck : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "4c63c8a2-5889-5177-9f66-8e5f755025a3"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/Charterino/AsStrongAsFuck"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L107-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4765f2099bf8fa8ebccd8cdcc561354f4aeba28c2473fd8556f1ef1d5d28dadd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "AsStrongAsFuck" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}