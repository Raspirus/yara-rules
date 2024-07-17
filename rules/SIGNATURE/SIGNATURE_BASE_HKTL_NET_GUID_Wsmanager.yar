rule SIGNATURE_BASE_HKTL_NET_GUID_Wsmanager : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b8c330dc-74aa-5a33-8af6-17c9beb8be81"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/guillaC/wsManager"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1136-L1150"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f335250f717cdcc2e9c6022a1fc22a61b4eec59a5c69c9359c2f7658081117b3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9480809e-5472-44f3-b076-dcdf7379e766" ascii wide
		$typelibguid0up = "9480809E-5472-44F3-B076-DCDF7379E766" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}