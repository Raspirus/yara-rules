rule SIGNATURE_BASE_MAL_Backnet_Nov18_1 : FILE
{
	meta:
		description = "Detects BackNet samples"
		author = "Florian Roth (Nextron Systems)"
		id = "f8575c5a-710d-5e97-91c1-5db454c6baf4"
		date = "2018-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/valsov/BackNet"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_backnet.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ea809a65a3cd786efe03ff7d831847e658851f76ee9dd084cb6c622b6e44c75f"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "4ce82644eaa1a00cdb6e2f363743553f2e4bd1eddb8bc84e45eda7c0699d9adc"

	strings:
		$s1 = "ProcessedByFody" fullword ascii
		$s2 = "SELECT * FROM AntivirusProduct" fullword wide
		$s3 = "/C netsh wlan show profile" wide
		$s4 = "browsertornado" fullword wide
		$s5 = "Current user is administrator" fullword wide
		$s6 = "/C choice /C Y /N /D Y /T 4 & Del" wide
		$s7 = "ThisIsMyMutex-2JUY34DE8E23D7" wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 2 of them
}