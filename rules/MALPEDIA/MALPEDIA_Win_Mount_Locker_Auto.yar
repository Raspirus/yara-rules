rule MALPEDIA_Win_Mount_Locker_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6832e6a1-eaa1-5e1c-99c0-2c5304573141"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mount_locker"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mount_locker_auto.yar#L1-L152"
		license_url = "N/A"
		logic_hash = "bff6076907046250738924c00fe6ba5da63e4a09d46fe90acd3aa54210bff35b"
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
		$sequence_0 = { 81f900000780 7503 0fb7c0 3d2e050000 }
		$sequence_1 = { f30f5905???????? 0f5ad0 66490f7ed0 e8???????? }
		$sequence_2 = { 4d8bc8 4c8bc2 4c8bf2 8bf1 }
		$sequence_3 = { 8bc8 81e10000ffff 81f900000780 7503 }
		$sequence_4 = { 488b0b 41b902000000 4533c0 33d2 }
		$sequence_5 = { 488d4df0 4889442428 4533c9 4533c0 }
		$sequence_6 = { 488bcb 488b15???????? e8???????? 85c0 }
		$sequence_7 = { 488364242000 4533c9 488b4c2458 33d2 c744243001000000 c744243c02000000 }
		$sequence_8 = { 4c8bf2 8bf1 33d2 33c9 }
		$sequence_9 = { ff15???????? 85c0 7509 f0ff05???????? }
		$sequence_10 = { b905000000 ff15???????? 3d040000c0 7494 85c0 }
		$sequence_11 = { 7505 e8???????? 833d????????00 7409 833d????????00 }
		$sequence_12 = { 8d442430 68???????? 50 ffd7 }
		$sequence_13 = { a1???????? 83f804 7515 68???????? }
		$sequence_14 = { 8bf0 85f6 7424 6800010000 }
		$sequence_15 = { ff15???????? 85c0 7409 f0ff05???????? eb1e 56 }

	condition:
		7 of them and filesize <368640
}