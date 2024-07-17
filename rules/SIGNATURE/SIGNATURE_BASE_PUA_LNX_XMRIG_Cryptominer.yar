
rule SIGNATURE_BASE_PUA_LNX_XMRIG_Cryptominer : FILE
{
	meta:
		description = "Detects XMRIG CryptoMiner software"
		author = "Florian Roth (Nextron Systems)"
		id = "bbdeff2e-68cc-5bbe-b843-3cba9c8c7ea8"
		date = "2018-06-28"
		modified = "2023-01-06"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/pua_xmrig_monero_miner.yar#L53-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "501bc5b2d38882f48d1ef972dbbd379afb89f2e7c9bf69192c7bee2e19384816"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"

	strings:
		$x1 = "number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
		$s2 = "'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
		$s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
		$s4 = ".nicehash.com" ascii

	condition:
		uint16(0)==0x457f and filesize <8000KB and (1 of ($x*) or 2 of them )
}