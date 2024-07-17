rule MALPEDIA_Win_Shylock_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c0c6612f-064a-5f55-82bb-f58e63a548a1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shylock"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.shylock_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "2cab0a97d5d39d5cf87c312cbde6ff184fa1776200cc626b918f5dce9951a83d"
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
		$sequence_0 = { e8???????? 8d8534ffffff 50 b8???????? e8???????? 59 50 }
		$sequence_1 = { 8db544ffffff e8???????? 8bc6 50 8d45f8 e8???????? ff30 }
		$sequence_2 = { c22c00 0fb64001 50 8d45c8 50 8b45d4 8b30 }
		$sequence_3 = { c745fc04010000 ff75e4 e8???????? 83c410 ff45f8 3d03010000 0f8559ffffff }
		$sequence_4 = { e8???????? 3c01 743b 8d8588feffff 50 b8???????? e8???????? }
		$sequence_5 = { 57 8b7d08 8b4d0c 8a4510 fc f2ae 7504 }
		$sequence_6 = { 8945b0 8d856cffffff 50 8b45fc ff7018 ff9540ffffff 898534ffffff }
		$sequence_7 = { 8d75f8 8bfc e8???????? 8d8504ffffff 50 ff7508 e8???????? }
		$sequence_8 = { 51 33d2 8d5df8 e8???????? 8d45ec e8???????? 8bf8 }
		$sequence_9 = { e8???????? e8???????? 59 59 8bf0 e8???????? 8d75fc }

	condition:
		7 of them and filesize <630784
}