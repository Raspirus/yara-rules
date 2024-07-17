import "pe"


rule ARKBIRD_SOLG_TA505_Bin_21Nov_1 : FILE
{
	meta:
		description = "module1.bin"
		author = "Arkbird_SOLG"
		id = "2f23653e-5158-5a64-86ee-a58048780661"
		date = "2019-11-21"
		modified = "2019-11-21"
		reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/20-11-19/Yara_Rule_TA505_Nov19.yar#L3-L30"
		license_url = "N/A"
		logic_hash = "133f202300a9e0428d20ce76bc832cf45cb5dacb05e39c21130d8d5cc39446ba"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "bfe610790d41091c37ae627472f5f8886357e713945ca8a5e2b56cd6c791f989"

	strings:
		$s1 = "intc.dll" fullword ascii
		$s2 = "?%?2?7?=?" fullword ascii
		$s3 = "Is c++ not java" fullword ascii
		$s4 = "4%5K5e5l5p5t5x5|5" fullword ascii
		$s5 = "KdaMt$" fullword ascii
		$s6 = ";*;9;Z;`;" fullword ascii
		$s7 = "<*<4<?<I<S<Y<" fullword ascii
		$s8 = "0'040A0K0U0]0k0" fullword ascii
		$s9 = "3 3(30363>3M3_3" fullword ascii
		$s10 = ": :9:A:F:R:W:t:z:" fullword ascii
		$s11 = "5'5,585@5H5P5f5n5v5~5" fullword ascii
		$s12 = "<,<2<:<@<h<n<" fullword ascii
		$s13 = "8+808:8T8b8j8p8" fullword ascii
		$s14 = "8!9<9K9g9o9z9" fullword ascii
		$s15 = ">(>6>D>N>U>f>p>" fullword ascii
		$s16 = ":!:,:>:J:X:^:c:i:v:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (pe.imphash()=="642f4619fb2d93cb205c65c2546516ca" and pe.exports("intc") or 8 of them )
}