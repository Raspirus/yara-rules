import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Crypter_Runtime_AV_S_Bypass : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "726cd57b-d88a-5854-b2e1-76d9bd71a155"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1652-L1666"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "368023cf6e78965696f676a45858b671ff75f329419ec4d7a02767c81e503027"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii wide
		$typelibguid0up = "C25E39A9-8215-43AA-96A3-DA0E9512EC18" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}