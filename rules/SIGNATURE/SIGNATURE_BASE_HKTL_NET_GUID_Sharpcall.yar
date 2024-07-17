import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcall : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "172415b6-0383-5da4-a88f-8ebe5daf9294"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/jhalon/SharpCall"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3935-L3949"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7084ac8956827fff5baefb92e117e0c64f13ab8f77cb5d034c31d874a6297047"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii wide
		$typelibguid0up = "C1B0A923-0F17-4BC8-BA0F-C87AFF43E799" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}