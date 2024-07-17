
rule MALPEDIA_Win_Carberp_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ca3e7da8-ad9c-59f4-8614-8b1382409083"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.carberp"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.carberp_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "1e5a666bd6ef8c024c58bd150c2d57a0675cba836a8af1e051301be69118758b"
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
		$sequence_0 = { b8???????? 50 6a00 50 e8???????? 8b4518 8945e4 }
		$sequence_1 = { 68f5a40f7d 6a0d 6a00 e8???????? 68da6772c2 6a0d 6a00 }
		$sequence_2 = { ff75fc 56 ff15???????? 8bf0 8d45f8 50 e8???????? }
		$sequence_3 = { 0f848d000000 6683f832 0f8483000000 6683f821 0f8548010000 57 8d8588fdffff }
		$sequence_4 = { 7407 50 e8???????? 59 ff45f4 8b45f4 3b45f0 }
		$sequence_5 = { 668945f6 58 6a72 668945f8 58 6a5c 668945fa }
		$sequence_6 = { ff7658 e8???????? 83c418 83665800 5e 5d c3 }
		$sequence_7 = { 59 59 85f6 7419 ff7510 56 6a04 }
		$sequence_8 = { 6800000040 ff7508 ffd0 8bf8 83ffff 7504 33c0 }
		$sequence_9 = { c645f867 c645f96c c645fa57 c645fb6e c645fc64 885dfd 895dc8 }

	condition:
		7 of them and filesize <491520
}