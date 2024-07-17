
rule MALPEDIA_Win_Wpbrutebot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ee6ef210-d105-53c3-a558-0e67b4040536"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wpbrutebot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.wpbrutebot_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "709c38b5efc64910ec1c02f61c4cfca810d098711a98c2359e209f406eb3230c"
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
		$sequence_0 = { 894f54 897758 89775c e9???????? 85c9 7515 c7475003000000 }
		$sequence_1 = { f7472c00010000 b35d 7411 8b4730 6a5d 8b4804 8b01 }
		$sequence_2 = { f6044dc81e5e0002 7410 8bc1 ba01000000 83f020 85d2 0f44c1 }
		$sequence_3 = { c645fc04 8d8dfcf4ffff e8???????? 68???????? 8bd0 c645fc05 8d8d14f5ffff }
		$sequence_4 = { ff742420 8b7a08 037c2420 89442448 c744244c01000000 897c2450 8b4a08 }
		$sequence_5 = { c781f0050000bfe45900 5b 83c408 c3 5f 5e 5d }
		$sequence_6 = { 7228 8bb504ffffff 8d8504ffffff 50 8bc8 e8???????? 8b8518ffffff }
		$sequence_7 = { 8b44245c a802 b800000000 0f45d8 895c241c 85f6 7410 }
		$sequence_8 = { f7e9 d1fa 8bc2 c1e81f 03c2 83f801 762b }
		$sequence_9 = { ffb7ec0c0000 6a01 53 e8???????? 8be8 83c410 }

	condition:
		7 of them and filesize <5134336
}