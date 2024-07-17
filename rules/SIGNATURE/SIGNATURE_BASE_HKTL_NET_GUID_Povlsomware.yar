rule SIGNATURE_BASE_HKTL_NET_GUID_Povlsomware : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0eba43d2-b415-5e72-9677-4a3238ff7c34"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/povlteksttv/Povlsomware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L154-L168"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "681603aa09b83f1a5a56c26204a4a5338c14627f977b29d3edc28a50149756d4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii wide
		$typelibguid0up = "FE0D5AA7-538F-42F6-9ECE-B141560F7781" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}