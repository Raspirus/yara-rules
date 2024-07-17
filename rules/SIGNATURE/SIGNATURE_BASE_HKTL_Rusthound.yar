rule SIGNATURE_BASE_HKTL_Rusthound : FILE
{
	meta:
		description = "Detect hacktool RustHound (Sharphound clone)"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d2fd79a5-9a1a-51de-920c-61653c8b0064"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://github.com/OPENCYBER-FR/RustHound"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4688-L4715"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "409f61a34d9771643246f401a9670f6f7dcced9df50cbd89a2e1a5c9ba8d03ab"
		hash = "b1a58a9c94b1df97a243e6c3fc2d04ffd92bc802edc7d8e738573b394be331a9"
		hash = "170f4a48911f3ebef674aade05184ea0a6b1f6b089bcffd658e95b9905423365"
		hash = "e52f6496b863b08296bf602e92a090768e86abf498183aa5b6531a3a2d9c0bdb"
		hash = "847e57a35df29d40858c248e5b278b09cfa89dd4201cb24262c6158395e2e585"
		hash = "4edfed92b54d32a58b2cfc926f98a56637e89850410706abcc469a8bc846bc85"
		hash = "feba0c16830ea0a13819a9ab8a221cc64d5a9b3cc73f3c66c405a171a2069cc1"
		hash = "21d37c2393a6f748fe34c9d2f52693cb081b63c3a02ca0bebe4a584076f5886c"
		hash = "874a1a186eb5808d456ce86295cd5f09d6c819375acb100573c2103608af0d84"
		hash = "bf576bd229393010b2bb4ba17e49604109e294ca38cf19647fc7d9c325f7bcd1"
		logic_hash = "386b734ad7f3cf02f096236c941033b3f905a3368b8a72dd63e91e6e94f12f8d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$rh1 = "rusthound" fullword ascii wide
		$rh2 = "Making json/zip files finished!" ascii wide

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0x457f) and 1 of ($rh*)
}