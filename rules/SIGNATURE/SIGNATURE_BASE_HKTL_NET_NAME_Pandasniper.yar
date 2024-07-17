rule SIGNATURE_BASE_HKTL_NET_NAME_Pandasniper : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "006400fb-7e6d-563b-ba78-17937983c9ba"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/QAX-A-Team/PandaSniper"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L777-L790"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c5a32f22a429777186d88f3fcfa79ad4d971e86ebd6117df74aae19728c6addd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "PandaSniper" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}