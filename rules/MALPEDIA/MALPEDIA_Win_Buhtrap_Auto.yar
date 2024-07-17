
rule MALPEDIA_Win_Buhtrap_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "25eb4b11-3715-52d0-a7c7-9dac6aa80ccc"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buhtrap"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.buhtrap_auto.yar#L1-L162"
		license_url = "N/A"
		logic_hash = "d4e0c8ac83aa0b6c13a2f72737ffccb143e82cce7ba2ea9d1a844cc8381c4b50"
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
		$sequence_0 = { 59 59 84c0 0f8435010000 }
		$sequence_1 = { 7423 8b44240c 33d2 6a64 59 f7f1 }
		$sequence_2 = { c3 b301 ebe1 55 8bec 83ec18 }
		$sequence_3 = { 6a00 50 8d442414 c744242c04000000 }
		$sequence_4 = { 6a06 8bce e8???????? 8a1d???????? 56 }
		$sequence_5 = { 0f8489000000 837d1400 747b 6a09 59 33c0 8d7c242c }
		$sequence_6 = { 7405 e8???????? 85f6 7907 32c0 e9???????? 8365f000 }
		$sequence_7 = { ffd6 57 ffd6 33c0 85db 0f94c0 5f }
		$sequence_8 = { 754e 6a01 53 50 }
		$sequence_9 = { 53 68???????? 890e 894604 e8???????? 50 }
		$sequence_10 = { 897dfc e8???????? 59 84c0 0f8497000000 3bdf }
		$sequence_11 = { 6aff ff742420 ff7624 ffd7 ff742418 e8???????? }
		$sequence_12 = { ffd7 6a00 689385e784 6a28 68???????? }
		$sequence_13 = { 894624 8b442414 894604 a808 7466 }
		$sequence_14 = { 753d 8b4e2c 83c104 e8???????? e8???????? }

	condition:
		7 of them and filesize <131072
}