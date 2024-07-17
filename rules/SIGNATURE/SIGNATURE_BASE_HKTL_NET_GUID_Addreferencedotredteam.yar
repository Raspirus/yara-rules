rule SIGNATURE_BASE_HKTL_NET_GUID_Addreferencedotredteam : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "59299a72-9b7a-5108-81c2-d8f6d2e99b20"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1917-L1931"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "34717e4864a7dc5c21525be09fcfe87da6b18e56b1956e5a34b0a669d8d6ab45"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii wide
		$typelibguid0up = "73C79D7E-17D4-46C9-BE5A-ECEF65B924E4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}