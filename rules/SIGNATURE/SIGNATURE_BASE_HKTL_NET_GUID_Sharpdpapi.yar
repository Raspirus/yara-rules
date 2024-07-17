rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpdpapi : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1394323f-b336-548f-925c-c276d439e9eb"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/SharpDPAPI"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1358-L1374"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5846d932bb8064a82e57f942d0c7a8feec4c8582bb2eac64be7cc662d60e6d6e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii wide
		$typelibguid0up = "5F026C27-F8E6-4052-B231-8451C6A73838" ascii wide
		$typelibguid1lo = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii wide
		$typelibguid1up = "2F00A05B-263D-4FCC-846B-DA82BD684603" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}