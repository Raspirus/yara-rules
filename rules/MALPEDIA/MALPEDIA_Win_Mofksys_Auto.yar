
rule MALPEDIA_Win_Mofksys_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d4eb461a-0f9d-55f8-ba8b-2ce33ab04b0d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mofksys"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mofksys_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "79cea3cada5c4d8bb821159689e5cf75c88595dc32d8f5768a4b2ed694d76584"
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
		$sequence_0 = { 50 e8???????? 8bd0 8d4de8 ffd6 8d8d60ffffff }
		$sequence_1 = { 894dd4 c745fc07000000 8b55d8 52 e8???????? ff15???????? 8b45d4 }
		$sequence_2 = { 83c40c c745fca1000000 ba???????? 8d4dc0 ff15???????? 8d4dc0 51 }
		$sequence_3 = { f7de 3bf0 7209 ff15???????? 8b4dc0 8b4118 0fafc6 }
		$sequence_4 = { ff15???????? 83c410 c745fc65000000 ba???????? 8d4dcc ff15???????? a1???????? }
		$sequence_5 = { ff15???????? 8bd0 8d8d7cfcffff ffd6 50 ffd7 }
		$sequence_6 = { a1???????? 8b4de4 50 51 ffd7 8bd0 8d4da8 }
		$sequence_7 = { 3bc3 7d12 68e0000000 68???????? 56 50 }
		$sequence_8 = { 83c201 0f80b2080000 52 8b45d0 50 68???????? }
		$sequence_9 = { e8???????? 8d4ddc ff15???????? c745fc0f000000 68???????? 6a00 ff15???????? }

	condition:
		7 of them and filesize <401408
}