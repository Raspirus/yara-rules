rule MALPEDIA_Win_Windealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f3b71a3e-a02a-5dce-bc43-cb374750ce4e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.windealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.windealer_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "d82b81175389182c804642799536612f0047302d818841ec0b2b4fd9f2036f88"
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
		$sequence_0 = { 50 56 e8???????? 83c410 8b4618 }
		$sequence_1 = { 6a00 ff15???????? 85c0 7407 50 ff15???????? 6a01 }
		$sequence_2 = { 6a04 50 6a04 68???????? 68???????? }
		$sequence_3 = { 50 56 e8???????? 83c410 8b4610 }
		$sequence_4 = { 53 56 57 68da070000 }
		$sequence_5 = { 56 57 68da070000 e8???????? }
		$sequence_6 = { 56 e8???????? 83c410 8b4610 }
		$sequence_7 = { 6a01 50 56 e8???????? 83c410 8bc7 }
		$sequence_8 = { 668b91d2070000 8a89d0070000 52 51 }
		$sequence_9 = { 8b4d08 668b91d2070000 8a89d0070000 52 51 }

	condition:
		7 of them and filesize <770048
}