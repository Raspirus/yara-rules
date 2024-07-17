
rule SIGNATURE_BASE_HKTL_NET_NAME_Revengerat_Stub_Cssharp : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "06dce4f9-4d7a-5976-a87a-07c539e5dbe8"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/NYAN-x-CAT/RevengeRAT-Stub-CSsharp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L137-L150"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a3bd1f8e52e6ed468b6a4fea83456ca813b69e2d676dfab687bbea5a746fed3c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "RevengeRAT-Stub-CSsharp" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}