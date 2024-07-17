import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Obfuscator : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d9988b00-1f10-5421-8ffe-49849a5d5902"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1056-L1070"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e56ec4a13dedbf987bf6f8ee1a8dcce31b82348053d541d836086a9923f3b934"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii wide
		$typelibguid0up = "8FE5B811-A2CB-417F-AF93-6A3CF6650AF1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}