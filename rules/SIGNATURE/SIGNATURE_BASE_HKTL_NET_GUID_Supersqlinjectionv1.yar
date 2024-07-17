rule SIGNATURE_BASE_HKTL_NET_GUID_Supersqlinjectionv1 : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "247bef0d-7873-51c7-97b8-1be6dfe7708d"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/shack2/SuperSQLInjectionV1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4539-L4553"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8e97bf351c4c7507f3cf40a2d7aa36c60906a8069bb3644ce6ef05911a4d9a5c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d5688068-fc89-467d-913f-037a785caca7" ascii wide
		$typelibguid0up = "D5688068-FC89-467D-913F-037A785CACA7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}