import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Forgecert : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "06b3ffbb-5a76-50a0-86dc-b9658bf2d7ec"
		date = "2023-03-18"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/ForgeCert"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5150-L5164"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6fecf2a1ce947de3978b4e10b1b02f35913a37551884f16eabd1d1d544d963b6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "bd346689-8ee6-40b3-858b-4ed94f08d40a" ascii wide
		$typelibguid0up = "BD346689-8EE6-40B3-858B-4ED94F08D40A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}