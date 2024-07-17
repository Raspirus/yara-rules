
rule MALPEDIA_Win_Unidentified_091_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8c2d9d9b-cb98-5dfc-90ce-01312105d94f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_091"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_091_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "5f25d4d54583311a39cbead5d516e9dd7eb57b96b31eb59a9b18d068eb7148c5"
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
		$sequence_0 = { e8???????? c744244801000000 488d4c2460 48895c2440 4c8d8734030000 48894c2438 4c8d0ddf721400 }
		$sequence_1 = { e8???????? 482be0 8b3a 488bd9 8b89d4050000 488bf2 85c9 }
		$sequence_2 = { e9???????? 488d8ab00e0000 e9???????? 488d8ad00e0000 e9???????? 488d8af00e0000 e9???????? }
		$sequence_3 = { 89742420 498b06 48634804 33d2 4a89543128 eb41 488b01 }
		$sequence_4 = { eb6f 4c8b5048 4d85d2 7514 c74424207a020000 418d527c 41b884000000 }
		$sequence_5 = { 742e c7814007000000000000 488d15b7081400 488b8938060000 41b895030000 e8???????? 48c7833806000000000000 }
		$sequence_6 = { eb0f 488bd3 488d0dabf12500 e8???????? 488b85d0010000 48634804 488d0524fe2500 }
		$sequence_7 = { e8???????? 90 488bcb e8???????? 85c0 7525 488b4c2438 }
		$sequence_8 = { ffc3 e8???????? 3bd8 7cc6 41f6c708 0f85d0000000 4c8d058d0c1100 }
		$sequence_9 = { eb03 890c90 8b4df3 48ffc2 4983c002 483bd1 72db }

	condition:
		7 of them and filesize <5777408
}