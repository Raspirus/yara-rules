rule SIGNATURE_BASE_HKTL_NET_GUID_Noamci : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5fab1551-9d35-53cf-a04f-c14370119553"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/med0x2e/NoAmci"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L250-L264"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4e4b7f6424ce77959bcc017e5f6d36059dda05df7ac09bc7055102c4ff2c10c0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii wide
		$typelibguid0up = "352E80EC-72A5-4AA6-AABE-4F9A20393E8E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}