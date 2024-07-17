import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Evilwmiprovider : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3a6cf00e-28c4-5e6f-a28d-b3f28fca6eed"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/sunnyc7/EvilWMIProvider"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L556-L570"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5999197c1ccc2b3e9043c1cd4f73ef607f46b8eab0cd93889263cc460a3ba2c8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii wide
		$typelibguid0up = "A4020626-F1EC-4012-8B17-A2C8A0204A4B" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}