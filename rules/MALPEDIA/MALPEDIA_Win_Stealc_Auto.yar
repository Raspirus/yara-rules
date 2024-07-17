rule MALPEDIA_Win_Stealc_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "539cf538-cfac-56e1-8a82-eaf8270c6c0b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealc"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stealc_auto.yar#L1-L108"
		license_url = "N/A"
		logic_hash = "6bf18991e2a395daac8cbfec9f407668e110581410c7e2de7aedba9cee95d9f0"
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
		$sequence_0 = { ff15???????? 85c0 7507 c685e0feffff43 }
		$sequence_1 = { 68???????? e8???????? e8???????? 83c474 }
		$sequence_2 = { 50 e8???????? e8???????? 83c474 }
		$sequence_3 = { e8???????? e8???????? 81c480000000 e9???????? }
		$sequence_4 = { 50 e8???????? e8???????? 81c484000000 }
		$sequence_5 = { e8???????? 83c460 e8???????? 83c40c }
		$sequence_6 = { e8???????? e8???????? 83c418 6a3c }
		$sequence_7 = { ff15???????? 50 ff15???????? 8b5508 8902 }
		$sequence_8 = { 50 ff15???????? 8b5508 8902 }
		$sequence_9 = { 7405 394104 7d07 8b4908 3bca 75f0 8bf9 }

	condition:
		7 of them and filesize <4891648
}