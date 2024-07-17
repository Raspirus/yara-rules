rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpdomainspray : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cffd3350-4a86-5035-ab15-adbc3ac2a0e9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/HunnicCyber/SharpDomainSpray"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2477-L2491"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cb8bbeebe23a1e9e77fae170f2742aa0aabfb88436f91dc78f94cc1bef70b2dd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii wide
		$typelibguid0up = "76FFA92B-429B-4865-970D-4E7678AC34EA" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}