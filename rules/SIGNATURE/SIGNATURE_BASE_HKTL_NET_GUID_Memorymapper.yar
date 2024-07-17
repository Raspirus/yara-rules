rule SIGNATURE_BASE_HKTL_NET_GUID_Memorymapper : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c978be10-315c-54e7-afea-f97e9a5f2d18"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/jasondrawdy/MemoryMapper"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3723-L3737"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ccdb8501b0f26aca352a13d5337d64c2eccff695bd052bd10bcd324c62c931e5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii wide
		$typelibguid0up = "B9FBF3AC-05D8-4CD5-9694-B224D4E6C0EA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}