rule MALPEDIA_Win_Nachocheese_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "eaa2162c-aba5-5a56-92b8-2694c1a819b5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nachocheese"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nachocheese_auto.yar#L1-L162"
		license_url = "N/A"
		logic_hash = "65398c7b0a5280da9a71f8939ca7f529421377deec37e9f371d0deba7b01dc67"
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
		$sequence_0 = { 3d9c000000 7c07 3d9f000000 7e0d 33c0 c3 05d13fffff }
		$sequence_1 = { 33f6 397508 0f8ec9000000 b8???????? 48 }
		$sequence_2 = { 2bfa 8d47fd 3901 8901 }
		$sequence_3 = { 02ca 880c3e 8a5005 32d1 8b4dfc 88143e 8a4c0105 }
		$sequence_4 = { 7305 83c303 eb1c 81fb00000100 }
		$sequence_5 = { 33c8 894710 8b4708 33c1 }
		$sequence_6 = { 7305 83c304 eb0f 81fb00000001 }
		$sequence_7 = { 7305 83c302 eb29 81fb00010000 }
		$sequence_8 = { 0f8539ffffff b8???????? 8d5001 8a08 }
		$sequence_9 = { 3d2cc00000 7f18 3d2bc00000 7d1b 3d9c000000 }
		$sequence_10 = { 763a b801011000 f7e6 8bc6 2bc2 d1e8 }
		$sequence_11 = { 0f84bf000000 6803010000 8895f0fcffff 8d95f1fcffff 6a00 52 e8???????? }
		$sequence_12 = { 50 e8???????? 8d8f0e010000 8bc1 83c430 8d5001 }
		$sequence_13 = { 02ca 8b55f4 880c3e 0fb6540205 }
		$sequence_14 = { 50 e8???????? b9???????? 83c424 }
		$sequence_15 = { 50 6a02 51 ff15???????? 83f801 }

	condition:
		7 of them and filesize <1064960
}