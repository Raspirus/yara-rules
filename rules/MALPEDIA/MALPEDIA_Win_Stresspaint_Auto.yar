
rule MALPEDIA_Win_Stresspaint_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1abc90df-5501-5268-be5d-9ffd5264cf78"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stresspaint"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stresspaint_auto.yar#L1-L151"
		license_url = "N/A"
		logic_hash = "34d2cc78b8a1b3b96faf71dac1e0e5a144bca4946a3f4a475da9ab8b6bdc6c9b"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 0103 014510 294514 83665800 }
		$sequence_1 = { 8d540208 8908 8d4a04 8a5202 51 }
		$sequence_2 = { 8d540203 3bea 7e4d 8b6c241c }
		$sequence_3 = { 0106 83560400 837d1c00 7494 }
		$sequence_4 = { 0103 ebaa 8b442408 56 }
		$sequence_5 = { 0103 014510 294674 8b4674 }
		$sequence_6 = { 0107 115f04 3bcb 7508 }
		$sequence_7 = { 0108 8b8e44010000 114804 8b4f18 }
		$sequence_8 = { 0107 83570400 85c9 7508 }
		$sequence_9 = { 010b 8945fc 8bc2 83530400 }
		$sequence_10 = { 8d5318 c7432400200000 66897312 c6431100 890a }
		$sequence_11 = { 8d540201 52 51 6a39 55 }
		$sequence_12 = { 8d540101 8bc5 89542430 8b542450 }
		$sequence_13 = { 8d5338 3b02 740a 41 83c250 3bcf }
		$sequence_14 = { 8d540201 8915???????? 33c0 8bd6 }
		$sequence_15 = { 8d540208 8b4500 c70100000000 8b4c2430 }

	condition:
		7 of them and filesize <1155072
}