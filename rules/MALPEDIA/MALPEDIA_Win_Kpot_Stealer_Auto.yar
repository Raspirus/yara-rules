
rule MALPEDIA_Win_Kpot_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e45631fb-3fb5-58e0-9b9b-6b34d42ff6ce"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kpot_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kpot_stealer_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "16f05178ea617d4330175d94df8b79c29f673ce62148ecbf2153af87111da7a0"
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
		$sequence_0 = { 03c6 50 ff75f4 e8???????? 59 59 8d4df8 }
		$sequence_1 = { 0bce 8bc1 c1e804 33c2 250f0f0f0f 33d0 }
		$sequence_2 = { 55 8bec ff7508 ff15???????? 83f8ff 7409 a8a7 }
		$sequence_3 = { 8b4604 8b5df4 03d2 8d445802 e8???????? }
		$sequence_4 = { 85c0 7427 8b45f8 03c6 50 }
		$sequence_5 = { 57 8bf8 8b4518 0fb67005 }
		$sequence_6 = { 8b45f4 c1e918 884b07 8945fc 8b45f0 83c308 ff4dec }
		$sequence_7 = { 5e 5b c9 c3 0fb70f 6685c9 7440 }
		$sequence_8 = { a8a7 7405 33c0 40 5d }
		$sequence_9 = { 8bc1 c1e810 884306 8b45f4 }

	condition:
		7 of them and filesize <219136
}