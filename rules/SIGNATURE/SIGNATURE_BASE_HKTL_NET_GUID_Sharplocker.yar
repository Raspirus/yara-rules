rule SIGNATURE_BASE_HKTL_NET_GUID_Sharplocker : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9525422a-d670-5475-abdc-b7ecd1ab9943"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/Pickfordmatt/SharpLocker"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3487-L3501"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "47cffdd5ffdf11c8afb16c031c6f44b0857ed369b2913a8c43b11bdb9d446171"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii wide
		$typelibguid0up = "A6F8500F-68BC-4EFC-962A-6C6E68D893AF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}