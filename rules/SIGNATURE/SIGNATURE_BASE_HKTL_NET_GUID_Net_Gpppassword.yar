import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Net_Gpppassword : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "a718f9fc-acf5-536e-81d6-d393cebe8f77"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/outflanknl/Net-GPPPassword"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3871-L3885"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "234f75bfcb9aee331f063bd7c1984a2696067400fde7a1938a4929cd809b1345"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii wide
		$typelibguid0up = "00FCF72C-D148-4DD0-9CA4-0181C4BD55C3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}