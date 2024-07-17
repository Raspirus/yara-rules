import "pe"


rule SIGNATURE_BASE_APT_MAL_RU_Turla_Kazuar_May20_1 : FILE
{
	meta:
		description = "Detects Turla Kazuar malware"
		author = "Florian Roth (Nextron Systems)"
		id = "cd0d1fa2-5303-55f8-90a7-4a699ec79230"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://www.epicturla.com/blog/sysinturla"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_kazuar.yar#L61-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "547ed3cd88057ab91a0804ecf515eacca04fcf6e490aed1ee0f6a26c3d6b8268"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "1fca5f41211c800830c5f5c3e355d31a05e4c702401a61f11e25387e25eeb7fa"
		hash3 = "2d8151dabf891cf743e67c6f9765ee79884d024b10d265119873b0967a09b20f"
		hash4 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"

	strings:
		$s1 = "Sysinternals" ascii fullword
		$s2 = "Test Copyright" wide fullword
		$op1 = { 0d 01 00 08 34 2e 38 30 2e 30 2e 30 00 00 13 01 }

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}