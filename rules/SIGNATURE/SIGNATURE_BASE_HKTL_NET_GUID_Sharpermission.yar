import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpermission : FILE
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d5027f51-f3ca-53cd-96d7-c355b5c2e6fa"
		date = "2021-01-21"
		modified = "2023-04-06"
		reference = "https://github.com/mitchmoser/SharPermission"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4843-L4857"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c22923057099a6a796cab36838728c0ae51a1c2a6f06c4a0c07415baadac6978"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii wide
		$typelibguid0up = "84D2B661-3267-49C8-9F51-8F72F21AEA47" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}