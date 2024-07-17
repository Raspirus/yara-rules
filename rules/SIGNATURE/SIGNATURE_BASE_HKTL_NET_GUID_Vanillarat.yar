import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Vanillarat : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9448e8d0-5bfc-5683-b633-284e43d24642"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/DannyTheSloth/VanillaRAT"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3739-L3755"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4241cbbf7cde175b6dfd27b59123e5e324f4356184dae07529dd021c0f3dbea9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii wide
		$typelibguid0up = "D0F2EE67-0A50-423D-BFE6-845DA892A2DB" ascii wide
		$typelibguid1lo = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii wide
		$typelibguid1up = "A593FCD2-C8AB-45F6-9AEB-8AB5E20AB402" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}