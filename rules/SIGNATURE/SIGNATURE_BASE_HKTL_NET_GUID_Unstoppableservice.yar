import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Unstoppableservice : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8c65fbee-d779-57a8-851b-7583be66c67a"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/malcomvetter/UnstoppableService"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3388-L3402"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1b2039d27bfaa624b47886e7a310e6b2ec0f6063e973e449270dfca54a7bdd7b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii wide
		$typelibguid0up = "0C117EE5-2A21-DEAD-BEEF-8CC7F0CAAA86" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}