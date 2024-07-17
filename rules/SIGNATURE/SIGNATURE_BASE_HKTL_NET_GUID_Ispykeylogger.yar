import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Ispykeylogger : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8607de67-b472-5afc-b2b9-cc758b5ec474"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/mwsrc/iSpyKeylogger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2493-L2513"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a323adff7a71022a88c0ea1d2d7ddba14f3cefab50c431c2972165ae412f2565"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii wide
		$typelibguid0up = "CCC0A386-C4CE-42EF-AAEA-B2AF7EFF4AD8" ascii wide
		$typelibguid1lo = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii wide
		$typelibguid1up = "816B8B90-2975-46D3-AAC9-3C45B26437FA" ascii wide
		$typelibguid2lo = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii wide
		$typelibguid2up = "279B5533-D3AC-438F-BA89-3FE9DE2DA263" ascii wide
		$typelibguid3lo = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii wide
		$typelibguid3up = "88D3DC02-2853-4BF0-B6DC-AD31F5135D26" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}