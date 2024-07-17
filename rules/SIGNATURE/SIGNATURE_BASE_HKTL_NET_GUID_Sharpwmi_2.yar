import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpwmi_2 : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e6ab2f5e-2a5a-5be9-9b66-96cb745fd199"
		date = "2020-12-28"
		modified = "2023-04-06"
		old_rule_name = "HKTL_NET_GUID_SharpWMI"
		reference = "https://github.com/GhostPack/SharpWMI"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3404-L3419"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2541e7eeb07ee9d018067c35765c9ad68c9c8ecf0baa723e410dde8c55dabbd0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii wide
		$typelibguid0up = "6DD22880-DAC5-4B4D-9C91-8C35CC7B8180" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}