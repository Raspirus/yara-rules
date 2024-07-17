rule SIGNATURE_BASE_MAL_Avemaria_RAT_Jul19 : FILE
{
	meta:
		description = "Detects AveMaria RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "960048cf-7a56-50cf-8498-549f900770d8"
		date = "2019-07-01"
		modified = "2023-12-05"
		reference = "https://twitter.com/abuse_ch/status/1145697917161934856"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_avemaria_rat.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a848ec579db6a07faeab5c855a56889b4bfeaa2958d0388f7fe8c6dcdea7e457"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "5a927db1566468f23803746ba0ccc9235c79ca8672b1444822631ddbf2651a59"

	strings:
		$a1 = "operator co_await" fullword ascii
		$s1 = "uohlyatqn" fullword ascii
		$s2 = "index = [%d][%d][%d][%d]" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}