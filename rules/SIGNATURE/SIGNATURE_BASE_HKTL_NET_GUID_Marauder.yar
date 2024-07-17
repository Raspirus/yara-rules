rule SIGNATURE_BASE_HKTL_NET_GUID_Marauder : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f2783477-2853-5dcd-95f5-9f1e07a4a6e8"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/maraudershell/Marauder"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1584-L1598"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8314db477f299931e6bb933be0234f18cfb3e36d6170b4aed1d482949aba75e8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii wide
		$typelibguid0up = "FFF0A9A3-DFD4-402B-A251-6046D765AD78" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}