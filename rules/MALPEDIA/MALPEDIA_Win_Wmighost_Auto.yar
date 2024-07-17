
rule MALPEDIA_Win_Wmighost_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0b0db58b-a86c-5fcd-a072-2eb1cc17420a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wmighost"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.wmighost_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "ca34789fba1f2bd4e0c465ce04013e3b6750b48b70cd8c7936238cd0c587d01a"
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
		$sequence_0 = { 52 e8???????? 83c40c 68e8030000 ff15???????? e9???????? }
		$sequence_1 = { 83c408 68???????? 8d8df0fcffff 51 }
		$sequence_2 = { c745fc00000000 8d4d08 e8???????? 50 8b45e8 8b08 }
		$sequence_3 = { 8945fc 837dfcff 7505 e9???????? 6a02 }
		$sequence_4 = { 8b550c 52 8d85f0fcffff 50 e8???????? 83c408 }
		$sequence_5 = { 33c1 8b55f8 8882c8304000 8b45f8 0fbe88c8304000 33d2 8a15???????? }
		$sequence_6 = { 66ab aa c685f0fcffff00 b940000000 33c0 8dbdf1fcffff }
		$sequence_7 = { 50 8b4df0 51 e8???????? c745fcffffffff 8d4d08 e8???????? }
		$sequence_8 = { 8dbdfdfeffff f3ab 66ab aa c685f0fcffff00 b940000000 }
		$sequence_9 = { 8955e4 8b45ec 50 8b4de4 51 6aff }

	condition:
		7 of them and filesize <49152
}