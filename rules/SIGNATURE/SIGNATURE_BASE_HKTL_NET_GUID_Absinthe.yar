import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Absinthe : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8f25593b-b9d2-5807-b299-b039ecfd43a5"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/cameronhotchkies/Absinthe"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2613-L2627"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f6736024464a7b7115f8b66ff985a47107cbdd7d6260e56586ade467b3ca6c2a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii wide
		$typelibguid0up = "9936AE73-FB4E-4C5E-A5FB-F8AAEB3B9BD6" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}