rule SIGNATURE_BASE_HKTL_NET_NAME_Fakefilemaker : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "2c87114f-5295-583f-b567-623d478ce0eb"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/DamonMohammadbagher/FakeFileMaker"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L3-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "27d402835f31b6383c837e90248ae5c6d22f4c267d52625ebfbcc2ee5099ccad"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "FakeFileMaker" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}