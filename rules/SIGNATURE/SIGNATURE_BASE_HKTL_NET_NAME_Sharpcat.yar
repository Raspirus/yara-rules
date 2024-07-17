
rule SIGNATURE_BASE_HKTL_NET_NAME_Sharpcat : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "a46be8d3-bf7b-5d86-b88b-33e6c8c152d8"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/Cn33liz/SharpCat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L297-L310"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b9e5946f8df1649e71abf014aa6579edbbc93a12ddcc56f8d85d97ae087c8711"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "SharpCat" ascii wide fullword
		$compile = "AssemblyTitle" ascii wide fullword

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}