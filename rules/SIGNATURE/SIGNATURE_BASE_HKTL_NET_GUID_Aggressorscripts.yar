import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Aggressorscripts : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d5903db5-010b-5b9d-8a5b-5d61aec52e7a"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/harleyQu1nn/AggressorScripts"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L314-L328"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "33982f1f91aa61c54f7c60236389ed78e0a23be5fc04abce6c6574e067522a23"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii wide
		$typelibguid0up = "AFD1FF09-2632-4087-A30C-43591F32E4E8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}