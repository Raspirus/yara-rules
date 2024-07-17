rule SIGNATURE_BASE_HKTL_NET_GUID_Inception : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8d18f1d5-9c9a-5258-9f96-fa24b702c6ad"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/two06/Inception"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3165-L3179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "333f2d92dad837ab1d9ce9bfbd0aac790026c9624d7f5e77c7a60fc6c4a72ca0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii wide
		$typelibguid0up = "03D96B8C-EFD1-44A9-8DB2-0B74DB5D247A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}