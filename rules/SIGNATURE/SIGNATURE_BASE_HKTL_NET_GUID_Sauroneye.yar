import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sauroneye : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3b624dde-a63e-58ac-a4db-af931f1d8553"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/vivami/SauronEye"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3503-L3519"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4f73dabd483ad1c45e6225ef8ef664f6db1ec75a6aa300a0a6efaa63e64b2c3a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii wide
		$typelibguid0up = "0F43043D-8957-4ADE-A0F4-25C1122E8118" ascii wide
		$typelibguid1lo = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii wide
		$typelibguid1up = "086BF0CA-F1E4-4E8F-9040-A8C37A49FA26" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}