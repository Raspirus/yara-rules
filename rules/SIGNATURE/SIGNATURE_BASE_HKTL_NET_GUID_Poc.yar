rule SIGNATURE_BASE_HKTL_NET_GUID_Poc : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5669bc1a-b32e-5ae7-bf94-8ed2a124c765"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/thezdi/PoC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2685-L2699"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "938b553912d069969326bc970d94c23749af3ef28a0b5ce2c49d9de54358f9bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "89f9d411-e273-41bb-8711-209fd251ca88" ascii wide
		$typelibguid0up = "89F9D411-E273-41BB-8711-209FD251CA88" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}