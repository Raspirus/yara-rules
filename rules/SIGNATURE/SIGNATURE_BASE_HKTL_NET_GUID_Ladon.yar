import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Ladon : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "57e3d2fa-d430-561b-9d42-cf58cda5ed7a"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/k8gege/Ladon"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L56-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f6fdcc7795808e6612be5db336ed04039b592fce459127b4f2d6170f520b0f85"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii wide
		$typelibguid0up = "C335405F-5DF2-4C7D-9B53-D65ADFBED412" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}