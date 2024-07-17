rule ARKBIRD_SOLG_Loader_JAVA_Kinsing_Aug_2020_Variant_B_1 : FILE
{
	meta:
		description = "Detect Kinsing Variant B"
		author = "Arkbird_SOLG"
		id = "7e0f9826-806c-5801-aab5-d2a8dba4e206"
		date = "2020-08-28"
		modified = "2020-08-29"
		reference = "https://twitter.com/JAMESWT_MHT/status/1299222198574632961"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-28/Loader_JAVA_Kinsing_Aug_2020_1.yar#L32-L52"
		license_url = "N/A"
		logic_hash = "5862d02b4e57024aa1c00b0a10ac9ee1a733890cf7d5b9ec7586f0506af113fc"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "e1471e8f9c1aa1457f819c0565a3444c53d3ec5fadf9f52ae988fde8e2d3a960"
		hash2 = "e70ea87d00567d33e20ed8649ef532eda966a8b5b1e83ea19728528d991eaaa0"

	strings:
		$ClassCode1 = { 4c 69 66 45 78 70 2e 6a 61 76 61 0c 00 3f 00 40 }
		$ClassCode2 = "java/lang/StringBuilder" fullword ascii
		$ClassCode3 = "java/net/URL" fullword ascii
		$ClassCode4 = { 6a 61 76 61 2f 6c 61 6e 67 2f 50 72 6f 63 65 73 73 42 75 69 6c 64 65 72 01 00 02 2e 2f }
		$Com1 = "chmod +x " fullword ascii
		$Com2 = { 53 4b 4c 01 00 02 6c 66 }
		$s1 = "kinsing" fullword ascii
		$s2 = "getAbsolutePath" fullword ascii

	condition:
		filesize <1KB and 3 of ($ClassCode*) and 1 of ($Com*) and 2 of ($s*)
}