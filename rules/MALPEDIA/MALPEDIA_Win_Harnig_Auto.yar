rule MALPEDIA_Win_Harnig_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4db6d1ff-ae88-5c90-aeff-64f63eac36fc"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.harnig"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.harnig_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "278559dff9c1abda460af9efb2388b0afb57c006c8438cf3b67adcf26f15e5f4"
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
		$sequence_0 = { c20800 6a05 ff742408 e8???????? c20400 53 }
		$sequence_1 = { 8bca 8dbde8fbffff f3ab 8d45f0 50 8d85e8fbffff }
		$sequence_2 = { ffd0 eb0b 68???????? ff15???????? 8bc8 }
		$sequence_3 = { 03c1 5e c9 c20800 8b542404 8a0a 33c0 }
		$sequence_4 = { 0bc6 5e c20800 6a05 }
		$sequence_5 = { 56 8d85e0fdffff 50 ffd3 8d45e0 50 }
		$sequence_6 = { 56 57 ba00010000 33c0 8bca 8dbde8f7ffff f3ab }
		$sequence_7 = { 85c0 746b 8b45f8 68f1cbf7ae }
		$sequence_8 = { ff5150 8b45fc 8b08 8d9524fdffff 52 8d9590feffff }
		$sequence_9 = { 8a0a 33c0 84c9 7419 56 8bf0 }

	condition:
		7 of them and filesize <49152
}