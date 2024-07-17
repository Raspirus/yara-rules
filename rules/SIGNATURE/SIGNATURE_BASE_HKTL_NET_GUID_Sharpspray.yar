rule SIGNATURE_BASE_HKTL_NET_GUID_Sharpspray : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e9312c96-be10-5942-a4da-1fe708cc6699"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/jnqpblc/SharpSpray"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L1040-L1054"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d2b757ccfaa924764b3c1869908e730022641e5c78919226370e84e84d6546ae"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii wide
		$typelibguid0up = "51C6E016-1428-441D-82E9-BB0EB599BBC8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}