
rule MALPEDIA_Win_Hyperssl_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2b769147-d4c5-504a-a0e4-deff8d9a685b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hyperssl"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.hyperssl_auto.yar#L1-L217"
		license_url = "N/A"
		logic_hash = "f5cbe0c98412e251badcd68fd5914804f5830187a82b3a89143d596e8e3b1b20"
		score = 75
		quality = 73
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
		$sequence_0 = { 0108 3310 c1c607 c1c210 }
		$sequence_1 = { 33c3 8b5c244c c1ee12 0bfe 33cf 8bf2 }
		$sequence_2 = { 0105???????? 8d8d5cffffff 89855cffffff 898560ffffff }
		$sequence_3 = { 2bf0 5f 8a10 301401 8a10 301406 40 }
		$sequence_4 = { 40 4f 75f2 5f 5e e9???????? c3 }
		$sequence_5 = { 7436 8b413c 03c1 742a }
		$sequence_6 = { 03c1 742a 8b4028 03c1 }
		$sequence_7 = { 0101 0100 0100 0100 }
		$sequence_8 = { 0100 0200 0200 0002 0002 }
		$sequence_9 = { 33c0 40 5d c20c00 6a08 }
		$sequence_10 = { 0108 3908 1bc9 f7d9 }
		$sequence_11 = { 8b4028 03c1 7423 56 57 }
		$sequence_12 = { ff15???????? 8bc8 85c9 7436 8b413c }
		$sequence_13 = { 0105???????? 8d558c 89458c 894590 }
		$sequence_14 = { c20c00 6a08 68???????? e8???????? 8b450c 83f801 }
		$sequence_15 = { 0101 014514 2bf3 8b5d0c }
		$sequence_16 = { 01442428 8b442428 884500 45 }
		$sequence_17 = { 017e0c 5f 8bc6 5e c20800 }
		$sequence_18 = { 017e0c 395e10 740f ff7610 }
		$sequence_19 = { 017e08 8bc3 e8???????? c20400 }
		$sequence_20 = { 017e0c 8d4d08 e8???????? 5f }
		$sequence_21 = { 011d???????? 5f 8935???????? 5e }
		$sequence_22 = { 017e08 50 e8???????? ff0d???????? }
		$sequence_23 = { 016b08 897b04 5f 5e }

	condition:
		7 of them and filesize <835584
}