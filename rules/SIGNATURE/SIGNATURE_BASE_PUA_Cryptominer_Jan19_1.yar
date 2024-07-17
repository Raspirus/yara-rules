rule SIGNATURE_BASE_PUA_Cryptominer_Jan19_1 : FILE
{
	meta:
		description = "Detects Crypto Miner strings"
		author = "Florian Roth (Nextron Systems)"
		id = "aebfdce9-c2dd-5f24-aa25-071e1a961239"
		date = "2019-01-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/pua_cryptocoin_miner.yar#L35-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7097d404e0317230a5f60fc66fbcb2a2a5315f8fd348a7e689aaf75c26684f9e"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"

	strings:
		$s1 = "Stratum notify: invalid Merkle branch" fullword ascii
		$s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
		$s3 = "User-Agent: cpuminer/" ascii
		$s4 = "hash > target (false positive)" fullword ascii
		$s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii

	condition:
		filesize <1000KB and 1 of them
}