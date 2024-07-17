import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Aviator : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "52acd520-52aa-5bb9-ab3b-66a940aa5f5a"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/Ch0pin/AVIator"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L346-L360"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4b25128df5cdc26152494f39656546974b3b04c5e4ec7d3084e27d0f6baf4ca0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii wide
		$typelibguid0up = "4885A4A3-4DFA-486C-B378-AE94A221661A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}