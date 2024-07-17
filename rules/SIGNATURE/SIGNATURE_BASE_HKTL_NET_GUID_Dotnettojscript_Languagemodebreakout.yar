import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Dotnettojscript_Languagemodebreakout : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8c8cf79f-8e69-5293-b27a-1f8593061627"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4827-L4841"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1f1651b896e62ee669e233403a9fb435adfb4f8965b6432452a1bb72b69bfe2c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii wide
		$typelibguid0up = "DEADB33F-FA94-41B5-813D-E72D8677A0CF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}