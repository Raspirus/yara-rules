rule SIGNATURE_BASE_HKTL_NET_GUID_Ewstoolkit : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "acde7744-d17f-5e47-a5e2-ff4f4c4d8093"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rasta-mouse/EWSToolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3421-L3435"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bc7f82779efec8a5e2a6a861a8e7a50e71e0b1e8891618f56bd12e0ce09eefc3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii wide
		$typelibguid0up = "CA536D67-53C9-43B5-8BC8-9A05FDC567ED" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}