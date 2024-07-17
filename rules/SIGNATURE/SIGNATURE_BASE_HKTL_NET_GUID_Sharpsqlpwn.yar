rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpsqlpwn : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b533d61a-8693-5c3c-8b31-2117262cad4e"
		date = "2022-11-21"
		modified = "2023-04-06"
		reference = "https://github.com/lefayjey/SharpSQLPwn.git"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4963-L4977"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2015c80084199bfedebe1591f02ffad5f31218351148d8087789b82523a39baa"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c442ea6a-9aa1-4d9c-9c9d-7560a327089c" ascii wide
		$typelibguid0up = "C442EA6A-9AA1-4D9C-9C9D-7560A327089C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}