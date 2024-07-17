rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpcompile : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c5e053c4-1c90-581a-a6c3-087b252254b2"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/SpiderLabs/SharpCompile"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1392-L1406"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "60ecb9a9fa90e096d6b5d830787989046f5f8441282f4d7a072c6d7435add42d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii wide
		$typelibguid0up = "63F81B73-FF18-4A36-B095-FDCB4776DA4C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}