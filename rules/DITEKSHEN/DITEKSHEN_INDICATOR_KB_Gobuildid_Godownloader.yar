
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Godownloader : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "da53c062-4a55-543d-b2b6-52acdf13febc"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1612-L1622"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "e0f5ee6ade4608a8b5c5bd02bf5aef0fcb9cb1fe1cc3a9d00b1ace91e5d0d33f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"1OzJqWaH4h1VtrLP-zk8/G9w32ha7_ziW1Fa-0Byj/gLtfhbXZ6i_W0e5e_tFF/ekG0n9hOcZjmwzRQnRqC\"" ascii
		$s2 = "Go build ID: \"kKxyj14l4NhGbuhOgzef/ab_yr_pUn6q2idYdoBhn/hFAjO_Yxc_rN6mHFuHM9/SmS3qmOyJBc_4xV_qg3B\"" ascii
		$s3 = "Go build ID: \"MiW7XJnQsBXxlBHro8GW/HMqQknRgJg-mCXomgFRt/88ccKMrfA_s6AcOJs3aM/jSUAU_l3RrMzlV6ANEYE\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}