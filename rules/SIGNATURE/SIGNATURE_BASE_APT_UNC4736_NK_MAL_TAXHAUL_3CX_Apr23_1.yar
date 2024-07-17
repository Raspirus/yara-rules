import "pe"


rule SIGNATURE_BASE_APT_UNC4736_NK_MAL_TAXHAUL_3CX_Apr23_1 : FILE
{
	meta:
		description = "Detects TAXHAUL (AKA TxRLoader) malware used in the 3CX compromise by UNC4736"
		author = "Mandiant"
		id = "25a80f98-03d6-59e6-84e6-6d847a6c591e"
		date = "2023-03-04"
		modified = "2023-12-05"
		reference = "https://www.3cx.com/blog/news/mandiant-initial-results/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_mal_gopuram_apr23.yar#L77-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f67af611d0b3d96e4aaf7b3b5e49c1fb536e61a430b79ac0a0560ef3773ba140"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$p00_0 = {410f45fe4c8d3d[4]eb??4533f64c8d3d[4]eb??4533f64c8d3d[4]eb}
		$p00_1 = {4d3926488b01400f94c6ff90[4]41b9[4]eb??8bde4885c074}

	condition:
		uint16(0)==0x5A4D and any of them
}