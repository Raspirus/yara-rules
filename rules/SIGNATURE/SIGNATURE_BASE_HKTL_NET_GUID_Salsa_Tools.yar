import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Salsa_Tools : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "50db578e-6ddb-54d1-a978-e3630a3548c3"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/Hackplayers/Salsa-tools"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1534-L1550"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4c02f8fb1f1dbad19360c28d0728ccb5a73db5d34127bd345fe5c4baeb87fc7c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "276004bb-5200-4381-843c-934e4c385b66" ascii wide
		$typelibguid0up = "276004BB-5200-4381-843C-934E4C385B66" ascii wide
		$typelibguid1lo = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii wide
		$typelibguid1up = "CFCBF7B6-1C69-4B1F-8651-6BDB4B55F6B9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}