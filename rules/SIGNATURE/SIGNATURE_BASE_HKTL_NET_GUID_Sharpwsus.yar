import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpwsus : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "f020eea9-4ff4-5242-b9b2-53284505dab4"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/nettitude/SharpWSUS"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5214-L5228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1511bb29b808146852555c7bc23cbdc9a4a2d70547fb1541790d1947a42d6089"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "42cabb74-1199-40f1-9354-6294bba8d3a4" ascii wide
		$typelibguid0up = "42CABB74-1199-40F1-9354-6294BBA8D3A4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}