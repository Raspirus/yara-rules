import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpexec : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5faff0aa-9ffe-5ac0-b9e0-ca9f79350036"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/anthemtotheego/SharpExec"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3133-L3147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0a8faa0abbd8654901a5b96dff22a635fd7d429a736fe9406c37e9bb724d2c89"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii wide
		$typelibguid0up = "7FBAD126-E21C-4C4E-A9F0-613FCF585A71" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}