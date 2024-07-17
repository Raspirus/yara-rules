
rule MALPEDIA_Win_Poscardstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "30b86ec5-11cf-5ead-8d33-f96f4fd997a4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poscardstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.poscardstealer_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "e2bc29fc53d916c8c6261d35dc13ec4aa0c9f6d2e8252ac3a60894a094beda3f"
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
		$sequence_0 = { c645fc01 e8???????? 8d4db8 51 50 8d55d4 }
		$sequence_1 = { 33d2 bb07000000 895de8 8975e4 }
		$sequence_2 = { 50 ff15???????? 8bf0 8d45b0 50 }
		$sequence_3 = { 03c8 83fb10 7303 8d55d4 }
		$sequence_4 = { 8bd1 c1fa05 c1e006 030495e0794200 eb05 b8???????? f6400420 }
		$sequence_5 = { c785e8feffff7ce74100 8b8520ffffff c645fc07 894598 }
		$sequence_6 = { 8b4da4 8b5590 8bc2 83f908 7303 }
		$sequence_7 = { 885dd4 e8???????? 8b0d???????? 8b35???????? 2bce b893244992 f7e9 }
		$sequence_8 = { 6800000040 50 ff15???????? 8bf0 8d45c4 50 }
		$sequence_9 = { e9???????? 8d8d58feffff e9???????? 8d8d10ffffff e9???????? 8d8d48ffffff e9???????? }

	condition:
		7 of them and filesize <362496
}