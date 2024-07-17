import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sitrep : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5f2ac63e-4be1-520c-82b1-1957027a63e2"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/mdsecactivebreach/sitrep"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3521-L3535"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c7fa4e8bd94d86218c22c1be99221b25406e7fbae54cfadb53f81720d167e8ce"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "12963497-988f-46c0-9212-28b4b2b1831b" ascii wide
		$typelibguid0up = "12963497-988F-46C0-9212-28B4B2B1831B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}