rule MALPEDIA_Win_Dimnie_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8c590346-8ec4-5fdf-b560-136be983395f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dimnie"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dimnie_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "0f3f067f034444fcc73a96e10a6a53b5dc6ee2b790aaefb3f5f862bcac5e875a"
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
		$sequence_0 = { 7605 8b450c eb54 8b550c 2b5508 83fa01 751c }
		$sequence_1 = { 33c0 eb6e 8b4508 3b450c 7505 8b4508 }
		$sequence_2 = { 8945f4 8b45f4 c1e804 8945f4 8b4df8 83c101 }
		$sequence_3 = { 8b550c 2b5508 8955f8 0f31 8945f4 8b45f4 c1e804 }
		$sequence_4 = { eb6e 8b4508 3b450c 7505 8b4508 eb61 }
		$sequence_5 = { 2b5508 83fa01 751c 0f31 }
		$sequence_6 = { 8b4508 eb61 8b4d08 3b4d0c 7605 8b450c }
		$sequence_7 = { 8b4d0c 8a55af 885102 837d1002 7e13 8b4508 0fb64802 }
		$sequence_8 = { 8b4510 8b08 83e107 8b5510 890a }
		$sequence_9 = { c70201000000 8b4508 8b08 83e10f 8b5508 890a 8b450c }

	condition:
		7 of them and filesize <212992
}