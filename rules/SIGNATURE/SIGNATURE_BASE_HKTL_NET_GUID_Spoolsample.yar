rule SIGNATURE_BASE_HKTL_NET_GUID_Spoolsample : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "38346575-cf5b-59bf-b2b2-21aacf05b8a4"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/leechristensen/SpoolSample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5448-L5462"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a57e5675d8e24a7288d070f8e764c5253797bf7ed3e4b1a3fba0a6e1777317e9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "640c36b4-f417-4d85-b031-83a9d23c140b" ascii wide
		$typelibguid0up = "640C36B4-F417-4D85-B031-83A9D23C140B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}