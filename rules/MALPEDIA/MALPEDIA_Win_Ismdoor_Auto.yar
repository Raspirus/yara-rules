rule MALPEDIA_Win_Ismdoor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e9177277-98bb-546b-913b-803dfeefda39"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ismdoor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ismdoor_auto.yar#L1-L156"
		license_url = "N/A"
		logic_hash = "489ff4b41f2f5bc83c56e62265d852f18476e83488ad914ef361d6d410139690"
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
		$sequence_0 = { 83f8ff 7504 32c0 eb05 c0e804 2401 84c0 }
		$sequence_1 = { 90 48897c2428 488d4da0 48894c2420 4c8d4d80 4c8bc3 }
		$sequence_2 = { 7405 488b00 ebdd 48894500 }
		$sequence_3 = { 89442420 48c7411807000000 48894110 668901 c744242001000000 }
		$sequence_4 = { 7613 498d4970 418bc2 41ffc2 }
		$sequence_5 = { 41ffc7 0f1f4000 418b16 488d4d38 e8???????? }
		$sequence_6 = { 8bd8 33c9 ff15???????? 488bc8 }
		$sequence_7 = { 488bd6 488bcf ff5030 488bc8 }
		$sequence_8 = { 884c0dd8 41 83f910 7cf6 }
		$sequence_9 = { 83f802 7506 c6473c00 eb04 40 }
		$sequence_10 = { 8b4804 83b9ec97480000 0f94c0 8845e4 c745fc01000000 }
		$sequence_11 = { c745f804000000 57 8a68fe 8d4004 8a48fb 8a78fc }
		$sequence_12 = { 886dff 81e61f000080 7905 4e 83cee0 46 }
		$sequence_13 = { e8???????? 83c404 c744246c0f000000 c744246800000000 c644245800 837c243c08 }
		$sequence_14 = { 75f2 8b7d10 8b07 3bf0 7421 8b4f04 }

	condition:
		7 of them and filesize <1933312
}