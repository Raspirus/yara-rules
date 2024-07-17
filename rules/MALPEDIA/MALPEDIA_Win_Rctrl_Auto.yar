rule MALPEDIA_Win_Rctrl_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "60ae096f-d5f7-57d0-b6f9-cb53f8d1b760"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rctrl"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rctrl_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "0c64a52ce76fbe6b25b4079783722f9c8bfa120e4543946e41c97eea8cb03d4d"
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
		$sequence_0 = { e8???????? 85c0 0f8440030000 8b10 8bc8 ff520c 83c010 }
		$sequence_1 = { 8bf0 56 6a00 6a00 ff15???????? 33c9 894508 }
		$sequence_2 = { 6a06 e8???????? cc b8???????? c3 55 8bec }
		$sequence_3 = { 8b473c 8985d4feffff e8???????? 85c0 0f85ef000000 814f2400000400 8b85d8feffff }
		$sequence_4 = { 33c0 40 8be5 5d c20800 6a14 b8???????? }
		$sequence_5 = { 898368040000 03c8 83bd7cffffff00 7433 8b855cffffff 8db328040000 03c1 }
		$sequence_6 = { 75cc 8d4dc8 e8???????? e9???????? e8???????? ffb6f8000000 e8???????? }
		$sequence_7 = { ff750c 8bd6 e8???????? 8b4518 8d0c3e 8d1400 }
		$sequence_8 = { 85c0 0f94c0 84c0 7423 6a00 6a00 57 }
		$sequence_9 = { ff7008 ff75f0 e8???????? 8bf0 eb02 }

	condition:
		7 of them and filesize <4315136
}