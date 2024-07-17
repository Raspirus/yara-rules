import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Evilfoca : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2b2f5f6f-4224-5013-9e85-0ac088826bea"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/ElevenPaths/EvilFOCA"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L3633-L3647"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d3302781414e5146ee8b5d7d2df8aa5d4be31308b7483200eb695e0c0048c279"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii wide
		$typelibguid0up = "F26BDB4A-5846-4BEC-8F52-3C39D32DF495" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}