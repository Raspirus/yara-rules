import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Clonevault : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3340a095-d926-5c85-b7ed-03151712538d"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/mdsecactivebreach/CloneVault"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4875-L4889"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b8a2be082e2444ac9bfa9dd820e08de147c8dbfc0573e7126bde39f18b917bfd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii wide
		$typelibguid0up = "0A344F52-6780-4D10-9A4A-CB9439F9D3DE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}