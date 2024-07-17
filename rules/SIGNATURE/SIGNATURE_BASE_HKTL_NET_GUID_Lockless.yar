import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Lockless : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f9b31f57-d721-5b6c-be63-b8309cba788a"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/GhostPack/LockLess"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4725-L4739"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b3f929e2a7ee7f3b82cafcffe89572e210ca817edeb261810b9a2191ba308c3d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii wide
		$typelibguid0up = "A91421CB-7909-4383-BA43-C2992BBBAC22" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}