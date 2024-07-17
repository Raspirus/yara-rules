
rule MALPEDIA_Win_Zebrocy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ddee4b03-585f-5184-85a4-c6cc1e810bdc"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zebrocy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zebrocy_auto.yar#L1-L161"
		license_url = "N/A"
		logic_hash = "619394d96ac2748c82d29651fdad853561cf847222687873937db9b64b7f21e0"
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
		$sequence_0 = { 014158 11515c e8???????? dc6360 }
		$sequence_1 = { 8bc6 33d2 66891478 8bc6 5f c3 8bff }
		$sequence_2 = { 0103 83c41c 5b 5e }
		$sequence_3 = { 83c438 68581b0000 ff15???????? 83bd00f7ffff08 8b85ecf6ffff 7306 8d85ecf6ffff }
		$sequence_4 = { 8b7508 837e0800 7610 8b4608 8d808c994200 fe08 }
		$sequence_5 = { 0110 8b7dd4 ba???????? 89470c }
		$sequence_6 = { 0103 8b0e ba???????? e8???????? }
		$sequence_7 = { 8b441a20 85c9 7f0d 7c05 83f801 7706 }
		$sequence_8 = { 0102 8b45d4 89500c 89c1 }
		$sequence_9 = { 014150 8b550c 115154 014158 }
		$sequence_10 = { 0f8553010000 837de400 7c5d 7f04 85f6 }
		$sequence_11 = { 0103 31d2 85ff 8b03 }
		$sequence_12 = { 7303 8d45b8 8b4dc8 03c8 8bc6 83fa10 }
		$sequence_13 = { 68???????? 6888000800 ff15???????? 8bf0 85f6 }
		$sequence_14 = { 0110 5e 5f 5d }
		$sequence_15 = { 3bc1 0f87c8090000 ff2485689c4100 33c0 838de8fdffffff }

	condition:
		7 of them and filesize <393216
}