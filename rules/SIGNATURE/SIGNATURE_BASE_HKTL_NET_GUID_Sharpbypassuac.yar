rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpbypassuac : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "474d40aa-4bcc-58b5-a129-40bbd3a89e99"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/FatRodzianko/SharpBypassUAC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1488-L1502"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "726b573fa957a2560d6f4e5e98497190ed8f8e1657427f14896e3aa439366c70"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii wide
		$typelibguid0up = "0D588C86-C680-4B0D-9AED-418F1BB94255" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}