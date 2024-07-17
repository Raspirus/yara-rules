rule SIGNATURE_BASE_HKTL_NET_NAME_Sharphose : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "89b00eb0-f1a2-5c77-a5b0-2329b08aadb7"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/ustayready/SharpHose"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L492-L505"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e3af2a156c2451f7ed2fe3e888fdf2ae080298f7eff56801ddc0c612f04902ee"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "SharpHose" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}