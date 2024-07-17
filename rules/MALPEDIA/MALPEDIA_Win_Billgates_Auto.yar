rule MALPEDIA_Win_Billgates_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2ccab9f1-e7c2-5897-af43-0d6c30857357"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.billgates"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.billgates_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "e0a8f89c836a13df9d06b620bc16eb3744a9d5b82a5ea28cb550060f6d08f1fc"
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
		$sequence_0 = { 3c11 7408 3c22 7404 3c30 }
		$sequence_1 = { 8d8809f9ffff b8c94216b2 f7e9 03d1 }
		$sequence_2 = { 3c58 7507 b802000000 eb02 }
		$sequence_3 = { 740c 3c11 7408 3c22 7404 3c30 }
		$sequence_4 = { 3c10 740c 3c11 7408 }
		$sequence_5 = { 83f8ff 750c ff15???????? 8bd8 f7db }
		$sequence_6 = { 3c11 7408 3c22 7404 }
		$sequence_7 = { ff15???????? 83f8ff 7508 ff15???????? f7d8 85c0 }
		$sequence_8 = { 3c10 740c 3c11 7408 3c22 }
		$sequence_9 = { 3c10 740c 3c11 7408 3c22 7404 }

	condition:
		7 of them and filesize <801792
}