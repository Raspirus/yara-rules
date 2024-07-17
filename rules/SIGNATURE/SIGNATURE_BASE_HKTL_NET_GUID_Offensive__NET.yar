import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Offensive__NET : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b98495fb-0338-5042-a7ce-d117204eb91e"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/mrjamiebowman/Offensive-.NET"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1983-L1997"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c26d29934fe3f7575ce1cd56bcf2571e95d5705bccdb1ca211ca7d46765d0fb4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii wide
		$typelibguid0up = "11FE5FAE-B7C1-484A-B162-D5578A802C9C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}