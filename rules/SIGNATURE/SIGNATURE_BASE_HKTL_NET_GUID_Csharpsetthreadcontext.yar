import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Csharpsetthreadcontext : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "883bb859-d5ab-501d-8c83-0c5a2cf1f6c8"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L6-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4e1d425c7921a4b80823275d0522ad74a94b12a3b137c54faa16a57ba5d60a89"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii wide
		$typelibguid0up = "A1E28C8C-B3BD-44DE-85B9-8AA7C18A714D" ascii wide
		$typelibguid1lo = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii wide
		$typelibguid1up = "87C5970E-0C77-4182-AFE2-3FE96F785EBB" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}