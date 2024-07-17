rule MALPEDIA_Win_Mokes_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5228f490-0d80-56e9-a8cc-72e35ac44ea7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mokes"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mokes_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "be97fd0567c8d98c1350b6cf1d21361ab6916096a99c6915f04160ab0a34cb53"
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
		$sequence_0 = { f6c101 0f85b0000000 8b442424 8b00 3d???????? 0f849f000000 8b4804 }
		$sequence_1 = { f20f1001 660f2fc1 0f28c3 f20f5cc7 0f47c1 f20f1008 f20f59c2 }
		$sequence_2 = { ff9050010000 8b8bac010000 8d83ac010000 89442424 85c9 740b 83790400 }
		$sequence_3 = { ff5030 89442410 83f8ff 7512 8b4508 c700???????? 5f }
		$sequence_4 = { f20f1025???????? f30fe6db f30fe6d2 f30fe6c9 f30fe6c0 f20f59dc f20f59d4 }
		$sequence_5 = { ffd0 8d4900 3d???????? 0f84cb000000 8b00 85c0 75ef }
		$sequence_6 = { e8???????? 8d4e14 e8???????? 8d4e34 e8???????? 5f 5e }
		$sequence_7 = { ff750c c70000000000 e8???????? 8b4508 8bce c706???????? c74608???????? }
		$sequence_8 = { e8???????? 8b75e4 8b4e0c 03ce 8b4604 8d0445feffffff 50 }
		$sequence_9 = { f20f1005???????? 660f2fc1 0f82ac010000 f20f108e88000000 f20f109690000000 f20f5c9680000000 f20f5c4e78 }

	condition:
		7 of them and filesize <18505728
}