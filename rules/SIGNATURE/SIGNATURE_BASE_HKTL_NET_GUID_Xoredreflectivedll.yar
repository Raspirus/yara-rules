import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Xoredreflectivedll : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9b584bfb-98ef-50ee-b546-780c4b210a1b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/r3nhat/XORedReflectiveDLL"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1700-L1716"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8df590cacf5922fcc9d059b34b88774b1afeb78b0fcffe3cc2d8578d20baf0a0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii wide
		$typelibguid0up = "C0E49392-04E3-4ABB-B931-5202E0EB4C73" ascii wide
		$typelibguid1lo = "30eef7d6-cee8-490b-829f-082041bc3141" ascii wide
		$typelibguid1up = "30EEF7D6-CEE8-490B-829F-082041BC3141" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}