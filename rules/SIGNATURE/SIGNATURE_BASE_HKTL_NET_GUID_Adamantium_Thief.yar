import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Adamantium_Thief : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "82225b2e-ab4a-50b8-a3fd-7ad4947d052e"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/LimerBoy/Adamantium-Thief"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L202-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "089fdba95fb53d412eca2e1188bf9b8211045793122a73ed6c0ea5ee5c386c47"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii wide
		$typelibguid0up = "E6104BC9-FEA9-4EE9-B919-28156C1F2EDE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}