import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpshares : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e96aa79b-1da2-5b0c-9ac2-b6e201e06ec6"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/djhohnstein/SharpShares/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2549-L2563"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3ff3dd2c1facaeefcfd7f784c4dae15a66ff5ba1de33bb007dbc8cc91c38c29e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii wide
		$typelibguid0up = "FE9FDDE5-3F38-4F14-8C64-C3328C215CF2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}