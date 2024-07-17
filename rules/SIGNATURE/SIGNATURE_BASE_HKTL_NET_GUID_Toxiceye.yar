rule SIGNATURE_BASE_HKTL_NET_GUID_Toxiceye : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0b7b62ce-9c24-5d81-8d87-22f6e461a62b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/LimerBoy/ToxicEye"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L414-L428"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "29c8be9e1500ff5799e7527482131e28dcea66077958d2c30126415769ad6ee0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii wide
		$typelibguid0up = "1BCFE538-14F4-4BEB-9A3F-3F9472794902" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}