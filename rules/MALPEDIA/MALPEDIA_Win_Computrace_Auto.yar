rule MALPEDIA_Win_Computrace_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4429b6f7-4609-5864-be9b-bd86b296052a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.computrace"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.computrace_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "d8751f69a58562c91660e3060ff3b6e112f846c07b191aab11a4034542037b61"
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
		$sequence_0 = { ff75cc e8???????? 3975e4 753a }
		$sequence_1 = { e8???????? 8a4002 8b0d???????? 8801 ff35???????? }
		$sequence_2 = { 740e 837de400 7408 037de4 897dd8 eba6 8b4514 }
		$sequence_3 = { 7503 800e08 e8???????? 894604 ff750c 8f4618 }
		$sequence_4 = { e30d 83c00a 51 ff750c 50 e8???????? }
		$sequence_5 = { e8???????? 837de400 0f8593feffff 8b86481b0000 83786c00 0f8483feffff }
		$sequence_6 = { 8b7508 80665cfe 33c0 8945fc 8845fb 6689461a 48 }
		$sequence_7 = { 7414 c745dc01000000 897d8c 6af1 }
		$sequence_8 = { e8???????? 8945e4 3bc6 7417 }
		$sequence_9 = { ff15???????? f7d8 1bc0 40 57 }

	condition:
		7 of them and filesize <73728
}