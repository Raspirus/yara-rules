rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpshot : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9d59cd53-53b1-57db-b391-eee4dd6feec0"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/tothi/SharpShot"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1967-L1981"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "843e7bb327314749a58e3d44356fcd9d7a2c349cb429f5bc593044894f17a15c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii wide
		$typelibguid0up = "057AEF75-861B-4E4B-A372-CFBD8322C8E1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}