rule SIGNATURE_BASE_HKTL_NET_GUID_Blacknet : FILE
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9fbb3c11-7b11-5910-9c8b-247aeefbaa87"
		date = "2020-12-30"
		modified = "2023-04-06"
		reference = "https://github.com/BlackHacker511/BlackNET"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4367-L4387"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a64b8d7d73292675e86ff73a0548582af36a6ed3c37fec52a3d2e012c49b9aa8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii wide
		$typelibguid0up = "C2B90883-ABEE-4CFA-AF66-DFD93EC617A5" ascii wide
		$typelibguid1lo = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii wide
		$typelibguid1up = "8BB6F5B4-E7C7-4554-AFD1-48F368774837" ascii wide
		$typelibguid2lo = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii wide
		$typelibguid2up = "983AE28C-91C3-4072-8CDF-698B2FF7A967" ascii wide
		$typelibguid3lo = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii wide
		$typelibguid3up = "9AC18CDC-3711-4719-9CFB-5B5F2D51FD5A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}