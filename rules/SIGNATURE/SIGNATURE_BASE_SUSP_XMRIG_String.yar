rule SIGNATURE_BASE_SUSP_XMRIG_String : FILE
{
	meta:
		description = "Detects a suspicious XMRIG crypto miner executable string in filr"
		author = "Florian Roth (Nextron Systems)"
		id = "8c6f3e6e-df2a-51b7-81b8-21cd33b3c603"
		date = "2018-12-28"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/pua_xmrig_monero_miner.yar#L72-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d2c3145c50939e7f407125f7b9312161724b7b1a6fcbf7e27d049e49e982c7e9"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"

	strings:
		$x1 = "xmrig.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}