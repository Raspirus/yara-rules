import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Csharp_Loader : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "bf0c3d93-cbea-54c7-b950-fd4e5a600d07"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L958-L972"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ff65463c10a7f4940f4dedef42707fe7feacded52d75014245e1961d1c80e845"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii wide
		$typelibguid0up = "5FD7F9FC-0618-4DDE-A6A0-9FAEFE96C8A1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}