rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpkatz : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ff084b4c-4b00-5504-85ee-d6d17b5be504"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/b4rtik/SharpKatz"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L120-L134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1e2e5be3256ad24da47096d8d7dbdaec139d4ca136a95957f505e1ec3bb3824f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii wide
		$typelibguid0up = "8568B4C1-2940-4F6C-BF4E-4383EF268BE9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}