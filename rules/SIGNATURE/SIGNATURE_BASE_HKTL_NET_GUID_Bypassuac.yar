import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Bypassuac : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "327f581e-1d8c-5d20-bdd7-a29810c619c9"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/cnsimo/BypassUAC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1234-L1250"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e466c4e3da0e8bc98eac148c67831df639befab716e0da5c779e3caacbf349a8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii wide
		$typelibguid0up = "4E7C140D-BCC4-4B15-8C11-ADB4E54CC39A" ascii wide
		$typelibguid1lo = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii wide
		$typelibguid1up = "CEC553A7-1370-4BBC-9AAE-B2F5DBDE32B0" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}