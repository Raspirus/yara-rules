
rule SIGNATURE_BASE_SUSP_LNX_SH_Cryptominer_Indicators_Dec20_1 : FILE
{
	meta:
		description = "Detects helper script used in a crypto miner campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "e376e0e1-1490-5ad4-8ca2-d28ca1c0b51a"
		date = "2020-12-31"
		modified = "2023-12-05"
		reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_crypto_miner.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4acd1b77307dbf23f95f7a2024209bee714c6931182aff16455ea6b7e4a6f287"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "3298dbd985c341d57e3219e80839ec5028585d0b0a737c994363443f4439d7a5"

	strings:
		$x1 = "miner running" fullword ascii
		$x2 = "miner runing" fullword ascii
		$x3 = " --donate-level 1 "
		$x4 = " -o pool.minexmr.com:5555 " ascii

	condition:
		filesize <20KB and 1 of them
}