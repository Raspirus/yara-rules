import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Rat_Shell : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8f206175-f7e4-5543-8059-24f102fcd4b9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/stphivos/rat-shell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1775-L1791"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2383483678c2a4b2545484c28aa81c2933c75a6bfb24dcfd6c989be90a2aca76"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii wide
		$typelibguid0up = "7A15F8F6-6CE2-4CA4-919D-2056B70CC76A" ascii wide
		$typelibguid1lo = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii wide
		$typelibguid1up = "1659D65D-93A8-4BAE-97D5-66D738FC6F6C" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}