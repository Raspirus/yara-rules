rule SIGNATURE_BASE_HKTL_NET_GUID_K8Fly : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3421e6fb-df65-5e2e-ae46-37f9c763c6a1"
		date = "2020-12-29"
		modified = "2023-04-06"
		reference = "https://github.com/zzwlpx/k8fly"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4278-L4292"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "16e9707f017aedf412ec98a466ec945e630ec1e294ee97e52a918d54be93db91"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii wide
		$typelibguid0up = "13B6C843-F3D4-4585-B4F3-E2672A47931E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}