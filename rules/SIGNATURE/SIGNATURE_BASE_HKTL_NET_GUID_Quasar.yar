import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Quasar : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b938cf7d-27fd-5fa2-b0e5-d4da5670f3ef"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/quasar/Quasar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3773-L3789"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "752602eecc404757f029aea481a58dc5b3d4c80f53fea1281e1ab8a78476d416"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii wide
		$typelibguid0up = "CFDA6D2E-8AB3-4349-B89A-33E1F0DAB32B" ascii wide
		$typelibguid1lo = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii wide
		$typelibguid1up = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}