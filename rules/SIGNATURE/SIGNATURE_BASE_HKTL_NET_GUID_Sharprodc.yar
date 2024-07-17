import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharprodc : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "60779e7a-048f-5095-b853-fd90c4f7449e"
		date = "2023-12-06"
		modified = "2024-04-24"
		reference = "https://github.com/wh0amitz/SharpRODC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5522-L5534"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3d24237804509d2bf241f7310843591608a9d7e8abb38eb324aa5909995ebfaf"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0 = "d305f8a3-019a-4cdf-909c-069d5b483613" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}