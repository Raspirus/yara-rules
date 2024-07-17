import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpimpersonation : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5815c5bd-e3e8-5f2f-b03e-8a05fb4f6e91"
		date = "2023-03-22"
		modified = "2023-04-06"
		reference = "https://github.com/S3cur3Th1sSh1t/SharpImpersonation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L5230-L5244"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c875b3e499b0fc6aa2833c3be88a4a4b93062e88cc8f1201eaf12e0b10f7cc95"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "27a85262-8c87-4147-a908-46728ab7fc73" ascii wide
		$typelibguid0up = "27A85262-8C87-4147-A908-46728AB7FC73" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}