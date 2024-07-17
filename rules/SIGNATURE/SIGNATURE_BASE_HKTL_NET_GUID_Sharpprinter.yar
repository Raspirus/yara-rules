rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpprinter : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "10270351-ad80-5330-971b-bc8f635f05f4"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/rvrsh3ll/SharpPrinter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3617-L3631"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "db7f131fa38756d53681792f3de2af44ace768e66c5318f61fa199900a8cdb8e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "41b2d1e5-4c5d-444c-aa47-629955401ed9" ascii wide
		$typelibguid0up = "41B2D1E5-4C5D-444C-AA47-629955401ED9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}