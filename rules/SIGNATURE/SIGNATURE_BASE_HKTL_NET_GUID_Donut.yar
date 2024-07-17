rule SIGNATURE_BASE_HKTL_NET_GUID_Donut : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "564dfd0a-af9b-505f-a6f0-de2a5c5c63f3"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/TheWover/donut"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4891-L4911"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cae0d358cda5330f69162aa3116d544f9ba16d37dcbcbf33f9938360b861b89a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii wide
		$typelibguid0up = "98CA74C7-A074-434D-9772-75896E73CEAA" ascii wide
		$typelibguid1lo = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii wide
		$typelibguid1up = "3C9A6B88-BED2-4BA8-964C-77EC29BF1846" ascii wide
		$typelibguid2lo = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii wide
		$typelibguid2up = "4FCDF3A3-AEEF-43EA-9297-0D3BDE3BDAD2" ascii wide
		$typelibguid3lo = "361c69f5-7885-4931-949a-b91eeab170e3" ascii wide
		$typelibguid3up = "361C69F5-7885-4931-949A-B91EEAB170E3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}