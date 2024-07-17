
rule MALPEDIA_Win_Unidentified_053_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b8635dce-dc5b-565f-a079-d654a222f110"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_053"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_053_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "466de537792d4c8cf5922d9a48018d257023e4a1753f3d834debb6d43be45c35"
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
		$sequence_0 = { 753c ff75e4 68???????? e8???????? 85c0 59 }
		$sequence_1 = { c1c603 81ea584dff93 8915???????? e8???????? 42 }
		$sequence_2 = { 8d3c85a8914100 833f00 bb00100000 7520 53 e8???????? }
		$sequence_3 = { ff75f0 50 ff91c4010000 8945f4 85c0 }
		$sequence_4 = { f7d7 c1c30e ffd0 890d???????? 87c7 2bc3 f7da }
		$sequence_5 = { f7db c1c017 e8???????? f7d1 }
		$sequence_6 = { 03f7 46 f7d8 81ebd4b243e9 c1c80c }
		$sequence_7 = { 3b8e50894100 0f8515010000 a1???????? 83f801 0f84df000000 3bc2 }
		$sequence_8 = { 81f669d8509c f7d2 686c6c6f63 e8???????? 4e 03c1 890d???????? }
		$sequence_9 = { 8b048588814100 234508 8b4e14 8d04c1 0fb64801 8b5004 83fa10 }

	condition:
		7 of them and filesize <294912
}