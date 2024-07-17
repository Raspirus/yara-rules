import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Whisker : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ecb0c59f-2111-58d9-8dc9-dfe005cad3be"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/eladshamir/Whisker"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5400-L5414"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "937998140d3487e7d490be50525ab6d42309e2198d3d2afe4e3c73ad14517b57"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "42750ac0-1bff-4f25-8c9d-9af144403bad" ascii wide
		$typelibguid0up = "42750AC0-1BFF-4F25-8C9D-9AF144403BAD" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}