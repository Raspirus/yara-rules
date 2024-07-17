rule SIGNATURE_BASE_HKTL_NET_GUID_Misc_Csharp : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d25fa706-2254-5a82-a961-f57a0daa447c"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/jnqpblc/Misc-CSharp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1022-L1038"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "446cf6773e679b18da31f63b52cdc6918e77ce5496848864c973ca5af60cdb05"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii wide
		$typelibguid0up = "D1421BA3-C60B-42A0-98F9-92BA4E653F3D" ascii wide
		$typelibguid1lo = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii wide
		$typelibguid1up = "2AFAC0DD-F46F-4F95-8A93-DC17B4F9A3A1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}