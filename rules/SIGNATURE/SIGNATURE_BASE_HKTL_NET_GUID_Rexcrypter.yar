rule SIGNATURE_BASE_HKTL_NET_GUID_Rexcrypter : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5ebbeab3-3e93-5544-8f74-3d1b47335d8b"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/syrex1013/RexCrypter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2885-L2899"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "82edeed1b6641c45ab7e41eb0d98416760c3af9998bf391905192d732e658cc1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii wide
		$typelibguid0up = "10CD7C1C-E56D-4B1B-80DC-E4C496C5FEC5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}