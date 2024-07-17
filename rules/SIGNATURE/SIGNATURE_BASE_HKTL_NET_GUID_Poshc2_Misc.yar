import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Poshc2_Misc : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "245803cb-63d8-5c75-b672-912091cf4a80"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/nettitude/PoshC2_Misc"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3649-L3665"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b6cabc8a50db469162024b13df8d69f57ca5ec008bddc647aee2a73dff9942c8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii wide
		$typelibguid0up = "85773EB7-B159-45FE-96CD-11BAD51DA6DE" ascii wide
		$typelibguid1lo = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii wide
		$typelibguid1up = "9D32AD59-4093-420D-B45C-5FFF391E990D" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}