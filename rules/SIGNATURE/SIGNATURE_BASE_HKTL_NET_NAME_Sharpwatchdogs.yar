
rule SIGNATURE_BASE_HKTL_NET_NAME_Sharpwatchdogs : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via name"
		author = "Arnim Rupp"
		id = "5343be58-879a-5fe7-9036-ee6a22d85f22"
		date = "2021-01-22"
		modified = "2023-12-05"
		reference = "https://github.com/RITRedteam/SharpWatchdogs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_names.yar#L282-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3b9410d7e502a5fd55e534d8fe79710d48cf65a0e9859bdd0fea6c8d32311df0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$name = "SharpWatchdogs" ascii wide
		$compile = "AssemblyTitle" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and all of them
}