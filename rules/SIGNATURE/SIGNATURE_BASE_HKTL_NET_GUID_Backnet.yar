rule SIGNATURE_BASE_HKTL_NET_GUID_Backnet : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "91824d18-f46b-5b95-b650-4d710d711cf9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/valsov/BackNet"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1879-L1899"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f1814ad6f6f96f9a9efc6d684c4e19203d84b191c0eef801c18f5b67787892bb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii wide
		$typelibguid0up = "9FDAE122-CD1E-467D-A6FA-A98C26E76348" ascii wide
		$typelibguid1lo = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii wide
		$typelibguid1up = "243C279E-33A6-46A1-BEAB-2864CC7A499F" ascii wide
		$typelibguid2lo = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii wide
		$typelibguid2up = "A7301384-7354-47FD-A4C5-65B74E0BBB46" ascii wide
		$typelibguid3lo = "982dc5b6-1123-428a-83dd-d212490c859f" ascii wide
		$typelibguid3up = "982DC5B6-1123-428A-83DD-D212490C859F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}