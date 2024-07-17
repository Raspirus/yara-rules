
rule MALPEDIA_Win_Iisniff_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4d48d0b9-4608-5fda-9d9c-52fef07b4d04"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iisniff"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.iisniff_auto.yar#L1-L161"
		license_url = "N/A"
		logic_hash = "eea8ed3537fc508bcc20c7dcdf7a5fa6fb525fac16191889baa1f35692f7bc88"
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
		$sequence_0 = { 85c0 7513 8b442414 8b4804 53 }
		$sequence_1 = { 8b8c240c000100 56 8d842414000100 50 51 }
		$sequence_2 = { 7507 be04000000 eb69 c645fc01 8b0f }
		$sequence_3 = { 55 56 8bb42488000000 57 33db }
		$sequence_4 = { 83d8ff 85c0 7537 8dbc24a4000000 e8???????? }
		$sequence_5 = { 5f 5b c20400 8b4038 8b08 890e }
		$sequence_6 = { 8b45cc ff704c e8???????? 59 83f8ff 0f852cffffff }
		$sequence_7 = { 56 8d4dd4 894598 e8???????? 8365fc00 56 8d4d9c }
		$sequence_8 = { 895c241c 89442420 e8???????? 8bf0 }
		$sequence_9 = { e8???????? 83c404 8d8c24fc000000 899c2448010000 89bc2444010000 }
		$sequence_10 = { 6a03 68000000c0 68???????? ff15???????? 6a02 }
		$sequence_11 = { e8???????? 8b4f3c 8b11 8d75c8 56 ff75cc }
		$sequence_12 = { ff75e8 e8???????? 834dfcff 8b45dc }
		$sequence_13 = { c3 ff7508 e8???????? 59 c3 833d????????00 7505 }
		$sequence_14 = { 64a300000000 80bc24a400000000 7409 6a00 6a00 e8???????? 8b410c }

	condition:
		7 of them and filesize <1441792
}