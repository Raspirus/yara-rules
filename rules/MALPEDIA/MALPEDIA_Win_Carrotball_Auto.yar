rule MALPEDIA_Win_Carrotball_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8d1dffb9-f801-5b51-998b-8e4431af5d29"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.carrotball"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.carrotball_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "8cb2e3b01c31931d0c5f23b61551aa799de8dd787a3493373f0ac01ba6f109d9"
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
		$sequence_0 = { ff15???????? eb36 68???????? 56 ff15???????? }
		$sequence_1 = { 6a04 58 6bc000 c7807430001002000000 6a04 }
		$sequence_2 = { 5f 8b4dfc 33cd 33c0 e8???????? 8be5 5d }
		$sequence_3 = { ffd6 5e 5f 8b4dfc 33cd 33c0 }
		$sequence_4 = { 68???????? ff15???????? eb36 68???????? 56 }
		$sequence_5 = { 8bf0 85f6 0f84ac000000 68???????? }
		$sequence_6 = { 56 ff15???????? 85c0 7432 8d85ecfdffff }
		$sequence_7 = { ff15???????? 8bf8 85ff 0f84d9000000 56 }
		$sequence_8 = { ff15???????? 8bf0 85f6 0f84ac000000 68???????? 56 ff15???????? }
		$sequence_9 = { 6bc000 c7807430001002000000 6a04 58 6bc000 }

	condition:
		7 of them and filesize <40960
}