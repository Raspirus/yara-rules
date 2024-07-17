import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Dinvisibleregistry : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "98409bbe-6346-5825-b7f7-c1afeac2b038"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3312-L3326"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a14dca802a63983d1c3974a4c195fd7bd5f256ace03d4bcea2d88eef6958931b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii wide
		$typelibguid0up = "31D576FB-9FB9-455E-AB02-C78981634C65" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}