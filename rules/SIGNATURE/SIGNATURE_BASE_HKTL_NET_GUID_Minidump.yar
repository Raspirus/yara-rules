import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Minidump : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "51f64c64-f3fa-5543-83fc-5f0bf881ef03"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/3xpl01tc0d3r/Minidump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1472-L1486"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "80142c0e96bca63f2b9991b3d6e2dfa7261bdde3a748fde96113d6f422b21e34"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii wide
		$typelibguid0up = "15C241AA-E73C-4B38-9489-9A344AC268A3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}