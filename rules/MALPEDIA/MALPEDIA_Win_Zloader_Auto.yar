rule MALPEDIA_Win_Zloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "97b40e53-0323-5f57-82eb-14236d63ac31"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zloader_auto.yar#L1-L384"
		license_url = "N/A"
		logic_hash = "d615cfd8aec428fea853159c669b5f75c64755d955e56d958f0ce28518a00d78"
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
		$sequence_0 = { 57 6a01 56 ffd0 89f7 89f8 }
		$sequence_1 = { 57 56 83ec0c 8b5d0c 8b7d10 8d75e8 89f1 }
		$sequence_2 = { 55 89e5 56 8b7508 ff36 e8???????? 83c404 }
		$sequence_3 = { 0fb7450c 8d9df0feffff 53 50 ff7508 e8???????? }
		$sequence_4 = { 57 56 8b7d08 57 e8???????? }
		$sequence_5 = { 0fb7c0 57 50 53 e8???????? 83c40c 89f1 }
		$sequence_6 = { 53 56 83ec0c 8d75ec 56 6aff }
		$sequence_7 = { 55 89e5 56 8b750c ff7508 e8???????? 83c404 }
		$sequence_8 = { 56 50 a1???????? 89c1 }
		$sequence_9 = { 5e 8bc3 5b c3 8b44240c }
		$sequence_10 = { 68???????? ff742408 e8???????? 59 59 84c0 741e }
		$sequence_11 = { e8???????? 59 84c0 7432 68???????? ff742408 e8???????? }
		$sequence_12 = { 57 56 50 8b4510 31db }
		$sequence_13 = { e8???????? 03c0 6689442438 8b442438 }
		$sequence_14 = { 6aff 50 e8???????? 8d857cffffff 50 }
		$sequence_15 = { 50 89542444 e8???????? 03c0 }
		$sequence_16 = { 6689442438 8b442438 83c002 668944243a }
		$sequence_17 = { 83c414 c3 56 ff742410 }
		$sequence_18 = { 99 52 50 8d44243c 99 52 50 }
		$sequence_19 = { c6043000 5e c3 56 57 8b7c2414 83ffff }
		$sequence_20 = { 50 56 56 56 ff7514 }
		$sequence_21 = { 83c408 5e 5d c3 55 89e5 57 }
		$sequence_22 = { 6a00 e8???????? 83c414 c3 8b542404 }
		$sequence_23 = { c7462401000000 c7462800004001 e8???????? 89460c }
		$sequence_24 = { 81c4a8020000 5e 5f 5b }
		$sequence_25 = { 55 89e5 53 57 56 81eca8020000 }
		$sequence_26 = { e9???????? 31c0 83c40c 5e 5f }
		$sequence_27 = { 0bc3 a3???????? e8???????? 8bc8 eb06 8b0d???????? 85c9 }
		$sequence_28 = { 89b42430010000 8b842430010000 8b842430010000 890424 c74424041c010000 e8???????? }
		$sequence_29 = { 89cf 8d0476 8945ec 890424 }
		$sequence_30 = { 50 6a72 e8???????? 59 }
		$sequence_31 = { 56 57 ff750c 33db 68???????? 6880000000 50 }
		$sequence_32 = { 8bc2 ebf7 8d442410 50 ff742410 ff742410 ff742410 }
		$sequence_33 = { 56 68???????? ff742410 e8???????? 6823af2930 56 ff742410 }
		$sequence_34 = { 50 e8???????? 68???????? 56 e8???????? 8bf0 59 }
		$sequence_35 = { 5f 5e 5b c3 8bc2 ebf8 53 }
		$sequence_36 = { 33f6 e8???????? ff7508 8d85f0fdffff 68???????? }
		$sequence_37 = { 68???????? 56 e8???????? 5e c3 56 }
		$sequence_38 = { 8d85f0fdffff 68???????? 6804010000 50 e8???????? 83c414 8d45fc }
		$sequence_39 = { 8bc2 ebf8 53 8b5c240c 55 33ed }

	condition:
		7 of them and filesize <1105920
}