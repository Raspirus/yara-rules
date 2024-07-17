import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Malsccm : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "4a88532b-e2bc-5ce9-828d-6ef62d91f6b9"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/nettitude/MalSCCM"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5432-L5446"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "429da06c863b73263f6de7acba0e8479cc2ad45af45d85ce846fce6f7e0b3b64"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5439cecd-3bb3-4807-b33f-e4c299b71ca2" ascii wide
		$typelibguid0up = "5439CECD-3BB3-4807-B33F-E4C299B71CA2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}