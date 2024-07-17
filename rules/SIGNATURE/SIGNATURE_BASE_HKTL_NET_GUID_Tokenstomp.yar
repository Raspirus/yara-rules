import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Tokenstomp : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e4266969-ab03-50dc-b5b1-f4bb1c9846f4"
		date = "2022-11-21"
		modified = "2023-04-06"
		reference = "https://github.com/MartinIngesen/TokenStomp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4997-L5011"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7bc49a8c654a6c6e3f0aa0378e91007c8ebdac90b536fbbfc123b09ff41eaa73"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8aac271f-9b0b-4dc3-8aa6-812bb7a57e7b" ascii wide
		$typelibguid0up = "8AAC271F-9B0B-4DC3-8AA6-812BB7A57E7B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}