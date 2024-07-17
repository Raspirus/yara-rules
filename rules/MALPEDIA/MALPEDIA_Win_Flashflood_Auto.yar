rule MALPEDIA_Win_Flashflood_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2b564813-7b00-54ab-b562-7a8de5369185"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flashflood"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.flashflood_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "3006626d1ecba778668c15e0aafe5a9ff5cdfe4debbbd864318346fc290d9ab7"
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
		$sequence_0 = { ff15???????? 8145f800809b07 8d45f8 50 }
		$sequence_1 = { 56 e8???????? 40 8945f8 0fbe06 50 }
		$sequence_2 = { c3 b8???????? c3 55 8bec 81ec88020000 }
		$sequence_3 = { 8bec 81ec10060000 56 6a5c ff750c ff15???????? 8bf0 }
		$sequence_4 = { 6bc90c 8b91f0914000 8955f4 8b450c 6bc00c }
		$sequence_5 = { ff5164 85c0 0f85c5010000 8d55f4 8b45ec 52 }
		$sequence_6 = { 33c0 eb0a 57 ff15???????? 6a01 58 5f }
		$sequence_7 = { 85f6 59 0f842b020000 ff7508 8d85f0fbffff 50 e8???????? }
		$sequence_8 = { 50 e8???????? 8d85c0fdffff 50 8d85c0fbffff ff7508 }
		$sequence_9 = { 83c62c 6a2e 56 ff15???????? 8b3d???????? 59 }

	condition:
		7 of them and filesize <114688
}