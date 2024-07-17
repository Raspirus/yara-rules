import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Logger : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "82937fef-8280-5bc6-af4a-55c5cb3a7553"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/xxczaki/logger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L792-L806"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0967d1278c72da256a647f45369d7ba4de8c17698d23d2e06d3723372a676634"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii wide
		$typelibguid0up = "9E92A883-3C8B-4572-A73E-BB3E61CFDC16" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}