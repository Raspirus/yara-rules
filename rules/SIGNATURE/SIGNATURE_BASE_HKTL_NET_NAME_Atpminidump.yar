rule SIGNATURE_BASE_HKTL_NET_NAME_Atpminidump : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "97981569-fe94-5600-8319-946edb4265e7"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/b4rtik/ATPMiniDump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L204-L217"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7498ed5d11b9c3646ebd2d1330a239c43e9c5b270b1778871c2821a2fefb5137"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "ATPMiniDump" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}