rule MALPEDIA_Win_Auriga_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3e414b5e-c2de-5c81-b4bc-c099cfe4cd7e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.auriga"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.auriga_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "cddd7158b581ccab9be1a01dbee785ac04d84e6e50041126742a64808d1b3062"
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
		$sequence_0 = { 90 5f bb???????? 81eb???????? 2bfb 8bf7 e8???????? }
		$sequence_1 = { 755b 817e0c03001200 7552 57 }
		$sequence_2 = { e8???????? c9 c20c00 ffb508fcffff 8b8504fcffff 8d8405fcfbffff }
		$sequence_3 = { 4a 3bda 745e 7345 2bd3 }
		$sequence_4 = { 7408 8b0d???????? 8908 56 8b7508 837e0400 7422 }
		$sequence_5 = { 53 53 6a01 6a01 56 ff15???????? 8945dc }
		$sequence_6 = { 84c0 7511 ff7510 ff15???????? }
		$sequence_7 = { ff45fc 8b4dec ff4df8 2bcb 295df4 ff45f8 }
		$sequence_8 = { ffd3 8b45fc 85c0 7539 ff750c 8d45f4 }
		$sequence_9 = { 8b85e8fbffff 85c0 7566 ffb5ecfbffff 8d85f0fbffff }

	condition:
		7 of them and filesize <75776
}