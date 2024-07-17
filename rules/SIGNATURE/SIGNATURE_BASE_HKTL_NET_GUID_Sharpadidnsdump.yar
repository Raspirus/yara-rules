rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpadidnsdump : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "51d50b22-4e73-5378-9e0d-ad7730987293"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/b4rtik/SharpAdidnsdump"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3791-L3805"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fe1bfdd03fabe40c2b885121de343890dd7eea22b51e9a1133d0842ba1080c78"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii wide
		$typelibguid0up = "CDB02BC2-5F62-4C8A-AF69-ACC3AB82E741" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}