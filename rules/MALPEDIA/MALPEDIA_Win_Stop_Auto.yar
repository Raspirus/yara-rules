
rule MALPEDIA_Win_Stop_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "fe824146-93e4-5101-ac02-1276fa1eda55"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stop"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stop_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "d919a89d4ce45439e081288fd345725318b761c87669a03e35d3c6db03d1320c"
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
		$sequence_0 = { 6a00 8d45e0 50 ffd6 85c0 75e2 6a64 }
		$sequence_1 = { ffd0 5d c3 8b0d???????? 33d2 85c9 }
		$sequence_2 = { 57 6a00 8bd9 6a00 6a12 ff33 }
		$sequence_3 = { 56 57 6a00 8bd9 6a00 6a12 }
		$sequence_4 = { ff750c ff7508 ffd0 5d c3 8b0d???????? }
		$sequence_5 = { ff15???????? 50 e8???????? c745fc00000000 }
		$sequence_6 = { 75e2 6a64 ff15???????? ffd3 }
		$sequence_7 = { 68???????? 6a00 6a00 ff15???????? 33c9 894604 85c0 }
		$sequence_8 = { 6a00 ff15???????? 33c9 894604 }
		$sequence_9 = { 6a00 ff15???????? 33c9 894604 85c0 5e 0f95c1 }

	condition:
		7 of them and filesize <6029312
}