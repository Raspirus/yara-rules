
rule SIGNATURE_BASE_SUSP_Doc_RTF_Ole2Link_Jun22 : FILE
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources"
		author = "Christian Burkard"
		id = "e9c83d58-6214-51d5-882a-4bd2ed6acc9a"
		date = "2022-06-01"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_doc_follina.yar#L96-L127"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
		logic_hash = "36cb711399197c694ac4fa4fd49cd5d587a830e152a138c81851b8e16301803d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sa = "\\objdata" ascii nocase
		$sb1 = "4f4c45324c696e6b" ascii
		$sb2 = "4F4C45324C696E6B" ascii
		$sc1 = "d0cf11e0a1b11ae1" ascii
		$sc2 = "D0CF11E0A1B11AE1" ascii
		$x1 = "68007400740070003a002f002f00" ascii
		$x2 = "68007400740070003A002F002F00" ascii
		$x3 = "680074007400700073003a002f002f00" ascii
		$x4 = "680074007400700073003A002F002F00" ascii
		$x5 = "6600740070003a002f002f00" ascii
		$x6 = "6600740070003A002F002F00" ascii

	condition:
		( uint32be(0)==0x7B5C7274 or uint32be(0)==0x7B5C2A5C) and $sa and 1 of ($sb*) and 1 of ($sc*) and 1 of ($x*)
}