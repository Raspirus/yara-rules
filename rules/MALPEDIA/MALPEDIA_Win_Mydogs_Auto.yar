rule MALPEDIA_Win_Mydogs_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8e0c4ca1-c33b-55e0-bdee-122873680dc3"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mydogs"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mydogs_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "64d7e86bc2c7d2208d4e1b71baa972c2ebb11908509ae447cb6fe3a57912500e"
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
		$sequence_0 = { 3db7000000 0f8444010000 68???????? 6804010000 68???????? e8???????? }
		$sequence_1 = { 884df3 c1fa18 8b5364 8bc2 8bce 0facc108 c1f808 }
		$sequence_2 = { 5d e9???????? 6a18 68???????? e8???????? 8b4508 8bd8 }
		$sequence_3 = { 894e64 8b4dec 894650 894658 894660 8b45ee 8d49c4 }
		$sequence_4 = { 50 ffb5e4eeffff ffb5f8eeffff ff15???????? 85c0 7515 5f }
		$sequence_5 = { 8bf9 53 895ddc 897de0 e8???????? }
		$sequence_6 = { 8b4dfc 33cd e8???????? 8be5 5d c3 8d85f4eeffff }
		$sequence_7 = { 50 8bcf c645ff4b e8???????? 6a01 8d450b 50 }
		$sequence_8 = { 1ddeb19d01 50 51 89530c e8???????? 894310 }
		$sequence_9 = { e8???????? 50 6800080000 53 89442434 e8???????? 83c414 }

	condition:
		7 of them and filesize <313344
}