rule MALPEDIA_Win_Webc2_Ugx_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "af26c213-66d2-5675-81ab-6f59f34ddb98"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_ugx"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.webc2_ugx_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "c0369798dbc9b5bf726746a205f3377c225f0e99dd41f08ae5697ccf08cc0c9d"
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
		$sequence_0 = { 8d458c 895dec 50 8d8568ffffff 50 }
		$sequence_1 = { 59 745e 8d4640 50 ff750c ffd3 59 }
		$sequence_2 = { 50 ff15???????? 85c0 7455 8d85a8feffff 53 50 }
		$sequence_3 = { ff9698060000 8bf8 85ff 0f84b5000000 8d866e0c0000 50 57 }
		$sequence_4 = { 8d85a8feffff 68???????? 50 ffd6 }
		$sequence_5 = { 50 ff55fc 8bc3 eb48 ff15???????? 56 }
		$sequence_6 = { 8d8584fdffff 50 ff55bc 50 8d8584fdffff 50 }
		$sequence_7 = { 8d8584f9ffff 57 50 ff55f0 }
		$sequence_8 = { ff5508 ff7510 e9???????? 53 }
		$sequence_9 = { 8d85a8feffff 68???????? 50 ffd6 8d85a8feffff 68???????? 50 }

	condition:
		7 of them and filesize <57344
}