
rule SIGNATURE_BASE_HKTL_NET_NAME_Metasploit_Sharp : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "b425f241-4887-5368-b42b-3fbbd3b769c6"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/VolatileMindsLLC/metasploit-sharp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L357-L370"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7a1c4e077e197a5cdca8cb12713abb3fa86a3f6ea8e8f2f632c9c8e42d829acc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "metasploit-sharp" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}