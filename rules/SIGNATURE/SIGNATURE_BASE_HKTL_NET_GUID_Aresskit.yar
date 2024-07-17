import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Aresskit : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8265cd84-c8e7-5654-9d3a-774dab52d938"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/BlackVikingPro/aresskit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1813-L1827"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d0a1c7000c4018ba3c7405e310cfddea8795745216467dfb79379af521889cc6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii wide
		$typelibguid0up = "8DCA0E42-F767-411D-9704-AE0BA4A44AE8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}