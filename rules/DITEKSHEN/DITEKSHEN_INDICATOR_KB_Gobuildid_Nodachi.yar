rule DITEKSHEN_INDICATOR_KB_Gobuildid_Nodachi : FILE
{
	meta:
		description = "Detects Golang Build IDs in Nodachi"
		author = "ditekSHen"
		id = "9d578768-7995-5fb0-8bf1-9c2221cdef80"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1655-L1666"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "177269623e0f3850c37c6b203d9a637fa92c0ed3fa823cc8d885f28cb383bf7d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"3AAyhKK0wFfCYLdz5oRV/zKyiBHCsAEyDIWhaW5AW/Rb8NLT3q8A2OLm6izDGP/8G9k_gjOTX_PXKna_IMj\"" ascii
		$s2 = "Go build ID: \"-eyFd8kbpwxUsutpqZn_/vqzQXX5Ra4qk1XHoqocW/wd-6gLzQKZyEyhVp7qOj/Jr14hyc7pLLgeIZNbfLD\"" ascii
		$s3 = "Go build ID: \"xDSqp4KGmd0SAf5irMGh/-kA7PGjKoJcvCgsZDStn/lHeQ1LQOVyQB2NnwIwFP/-D5oEBc23ND7IGLTESdM\"" ascii
		$s4 = "Go build ID: \"67RcwNspLH__QJrElMcB/zMJf7Go1s0ZoXqd30Lb_/NaJl4rfcuLEG5LeZ-Y4k/MzFNvW79enRRdx3LmA47\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}