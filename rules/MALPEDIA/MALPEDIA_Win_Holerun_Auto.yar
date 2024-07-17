
rule MALPEDIA_Win_Holerun_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3860635a-d58f-5696-9faf-227bf0bff05b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.holerun"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.holerun_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "5a5dd43f05b56cbfa86f75c5f65da136c78c894cffec56359e16aa1bc679245f"
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
		$sequence_0 = { 85c0 740c c785ec00000000000000 eb63 488b05???????? }
		$sequence_1 = { e8???????? 8b45c4 83f840 7472 8b45c4 83f804 }
		$sequence_2 = { c744242000010000 41b901000000 41b800000000 ba03000000 4889c1 }
		$sequence_3 = { 488b85e0000000 488b4020 4889c1 488b05???????? ffd0 }
		$sequence_4 = { ffd0 488b85e0000000 488b4020 4889c1 488b05???????? }
		$sequence_5 = { ffd0 8b85cc030000 4881c458040000 5b 5d c3 }
		$sequence_6 = { 4883c00f 48c1e804 48c1e004 e8???????? 4829c4 }
		$sequence_7 = { eb1e 8345f401 488345f828 488b45e8 0fb74006 0fb7c0 }
		$sequence_8 = { c705????????00000000 c705????????00000000 8b45fc 8905???????? }
		$sequence_9 = { 488b4d10 e8???????? 4885c0 7507 b8ffffffff eb05 }

	condition:
		7 of them and filesize <156672
}