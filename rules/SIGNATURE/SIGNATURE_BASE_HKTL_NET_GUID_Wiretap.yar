import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Wiretap : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5513a295-8907-5a9c-adca-760b33004229"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/djhohnstein/WireTap"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5278-L5292"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1e2199f7d4a01985edd2b4a071b928a3329e4f0f39d786608fdbbae1a01783fe"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "b5067468-f656-450a-b29c-1c84cfe8dde5" ascii wide
		$typelibguid0up = "B5067468-F656-450A-B29C-1C84CFE8DDE5" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}