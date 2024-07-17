rule SIGNATURE_BASE_PUA_Crypto_Mining_Commandline_Indicators_Oct21 : SCRIPT FILE
{
	meta:
		description = "Detects command line parameters often used by crypto mining software"
		author = "Florian Roth (Nextron Systems)"
		id = "afe5a63a-08c3-5cb7-b4b1-b996068124b7"
		date = "2021-10-24"
		modified = "2023-12-05"
		reference = "https://www.poolwatch.io/coin/monero"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/pua_cryptocoin_miner.yar#L54-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7ae1a77d8ff02ec539ce2b8be668530c3f509f0c408dfa7f2b749b0a4d6f45b7"
		score = 65
		quality = 85
		tags = "SCRIPT, FILE"

	strings:
		$s01 = " --cpu-priority="
		$s02 = "--donate-level=0"
		$s03 = " -o pool."
		$s04 = " -o stratum+tcp://"
		$s05 = " --nicehash"
		$s06 = " --algo=rx/0 "
		$se1 = "LS1kb25hdGUtbGV2ZWw9"
		$se2 = "0tZG9uYXRlLWxldmVsP"
		$se3 = "tLWRvbmF0ZS1sZXZlbD"
		$se4 = "c3RyYXR1bSt0Y3A6Ly"
		$se5 = "N0cmF0dW0rdGNwOi8v"
		$se6 = "zdHJhdHVtK3RjcDovL"
		$se7 = "c3RyYXR1bSt1ZHA6Ly"
		$se8 = "N0cmF0dW0rdWRwOi8v"
		$se9 = "zdHJhdHVtK3VkcDovL"

	condition:
		filesize <5000KB and 1 of them
}