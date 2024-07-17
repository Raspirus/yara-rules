import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Memscan : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "35175fe1-a583-50d1-8b0c-71f19b898817"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/nccgroup/memscan"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3455-L3469"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "099c6dfc9f30e56eca9834431eb527194e0302c9c6ef88f3c4fc91837a7aad7a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "79462f87-8418-4834-9356-8c11e44ce189" ascii wide
		$typelibguid0up = "79462F87-8418-4834-9356-8C11E44CE189" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}