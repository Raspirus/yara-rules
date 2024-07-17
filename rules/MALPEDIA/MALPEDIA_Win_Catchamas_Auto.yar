rule MALPEDIA_Win_Catchamas_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f5823958-4dc9-52e1-b587-ac7a6b699e31"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catchamas"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.catchamas_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "49e84bf121f6f46a8c4833df80092f815e20586f9bd57ea545ff931ae803e6c2"
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
		$sequence_0 = { ffd6 6808080000 8d54246c 52 }
		$sequence_1 = { 5f 5e 8b8c247c200000 33cc e8???????? }
		$sequence_2 = { 6a00 ff15???????? e8???????? 8bcb 8b5c244c 51 }
		$sequence_3 = { 6683f814 0f84c4080000 833d????????00 0f85af000000 }
		$sequence_4 = { 50 bf01000000 ff15???????? 56 ff15???????? 85ff 0f851a010000 }
		$sequence_5 = { 50 8d8c2494100000 68???????? 51 ff15???????? 83c42c 33c0 }
		$sequence_6 = { 84c0 8b45e0 7409 e8???????? 8bfc eb32 }
		$sequence_7 = { ffd7 6a0a 56 8be8 ffd7 8bf8 }
		$sequence_8 = { 83e802 0f84bf090000 83e80d 0f845a090000 }
		$sequence_9 = { 51 57 8bf0 50 ebbd e8???????? }

	condition:
		7 of them and filesize <368640
}