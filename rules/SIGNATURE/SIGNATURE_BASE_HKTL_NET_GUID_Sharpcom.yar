rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcom : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "94da3da4-a8aa-5735-9a04-1f2447a330aa"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rvrsh3ll/SharpCOM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3149-L3163"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c11955ce6a0a56de198b22d3716ce496573374847004a62f4b3a682edaa68ebe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii wide
		$typelibguid0up = "51960F7D-76FE-499F-AFBD-ACABD7BA50D1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}