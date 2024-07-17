rule MALPEDIA_Win_Formbook_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5884ccaf-7c22-509b-b936-d78ce47dc38a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.formbook_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "1856083163db4d487acf8602c72ba34a2aeebb6a0e8b028efa10c5ca24fd0c49"
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
		$sequence_0 = { 5b 5f 5e 8be5 5d c3 8d0476 }
		$sequence_1 = { 6a0d 8d8500fcffff 50 56 e8???????? 8d8d00fcffff 51 }
		$sequence_2 = { 56 e8???????? 8d4df4 51 56 e8???????? 8d55e4 }
		$sequence_3 = { c3 3c04 752b 8b7518 8b0e 8b5510 8b7d14 }
		$sequence_4 = { 56 e8???????? 83c418 395df8 0f85a0000000 8b7d18 395f10 }
		$sequence_5 = { c745fc01000000 e8???????? 6a14 8d4dec 51 50 }
		$sequence_6 = { e8???????? 83c428 8906 85c0 75a8 5f 33c0 }
		$sequence_7 = { 56 e8???????? 6a03 ba5c000000 57 56 66891446 }
		$sequence_8 = { 3b75d0 72c0 8d55f8 52 e8???????? }
		$sequence_9 = { 8d8df6f7ffff 51 c745fc00000000 668985f4f7ffff e8???????? 8b7508 }

	condition:
		7 of them and filesize <371712
}