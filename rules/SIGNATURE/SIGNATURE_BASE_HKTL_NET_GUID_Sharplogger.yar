import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharplogger : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5cce395b-4f6f-5015-b45e-7eb79853296a"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/djhohnstein/SharpLogger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2371-L2385"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a5118f0df57a4d9b0a7d682a016866ef5ae20c52e078223d72fc060774e17f48"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii wide
		$typelibguid0up = "36E00152-E073-4DA8-AA0C-375B6DD680C4" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}