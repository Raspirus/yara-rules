rule SIGNATURE_BASE_HKTL_NET_GUID_Stracciatella : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5b1a8102-6d59-5f2f-8ae2-b3c1f75a561d"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/mgeeky/Stracciatella"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L776-L790"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bae17954d54753fe1ce9c04c16fc8bdf43c11994f53a13106441170e310dc3d5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii wide
		$typelibguid0up = "EAAFA0AC-E464-4FC4-9713-48AA9A6716FB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}