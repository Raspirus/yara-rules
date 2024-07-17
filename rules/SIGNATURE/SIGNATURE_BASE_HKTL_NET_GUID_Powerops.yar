rule SIGNATURE_BASE_HKTL_NET_GUID_Powerops : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "3ef9f099-13c9-5b6f-8615-232240530078"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/fdiskyou/PowerOPS"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2765-L2779"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "211a96940c5cbca143471268500be46c13dc58469d2386b2dc7f8ff1f05a2c52"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii wide
		$typelibguid0up = "2A3C5921-7442-42C3-8CB9-24F21D0B2414" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}