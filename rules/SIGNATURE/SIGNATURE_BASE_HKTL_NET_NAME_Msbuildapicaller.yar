
rule SIGNATURE_BASE_HKTL_NET_NAME_Msbuildapicaller : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "143da57f-b01f-5688-b741-1bc4d06cd7d1"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/rvrsh3ll/MSBuildAPICaller"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L417-L430"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3c1f33c759e6331c562dbf76ce7e34ee82d10070e331d0967143d9d7fad077fc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "MSBuildAPICaller" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}