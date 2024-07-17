
rule MALPEDIA_Win_Lockbit_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "945a5bdc-50cc-5372-b470-aafc3e12d474"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lockbit_auto.yar#L1-L203"
		license_url = "N/A"
		logic_hash = "ef292234a38c5f85ea42d6220d555a65163be7c7bef94693195ea2cefdb10cc0"
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
		$sequence_0 = { 0f28c8 660f73f904 660fefc8 0f28c1 660f73f804 }
		$sequence_1 = { 50 e8???????? 8d858cfeffff 50 8d45c0 50 8d45a0 }
		$sequence_2 = { fec1 47 4e 85f6 75d2 5d }
		$sequence_3 = { 56 57 8d9d84fcffff b900c2eb0b e2fe e8???????? 53 }
		$sequence_4 = { 6683f866 7706 6683e857 eb17 6683f830 720c 6683f839 }
		$sequence_5 = { 33db 55 8b6d10 8bc1 }
		$sequence_6 = { 8d8550fdffff 50 6a00 ff15???????? }
		$sequence_7 = { 33c0 8d7df0 33c9 53 0fa2 }
		$sequence_8 = { f745f800000002 740c 5f 5e }
		$sequence_9 = { 02d3 8a5c1500 8a541d00 8a541500 fec2 8a441500 }
		$sequence_10 = { 33d0 8bc1 c1e810 0fb6c0 c1e208 }
		$sequence_11 = { 53 56 57 33c0 8b5d14 33c9 33d2 }
		$sequence_12 = { 8d45f8 50 8d45fc 50 ff75fc ff75f4 }
		$sequence_13 = { e9???????? 6683f841 720c 6683f846 7706 6683e837 }
		$sequence_14 = { 6a00 6a00 6800000040 ff75d4 }
		$sequence_15 = { 5b 8907 897704 894f08 89570c f745f800000002 740c }
		$sequence_16 = { 214493fc 8b5df8 8bc3 43 }
		$sequence_17 = { 7407 8bce e8???????? 837b0402 }
		$sequence_18 = { 7414 663901 740f 0f1f440000 }
		$sequence_19 = { 1bdb 83e30b 83c328 ff7518 8b7d08 8d049500000000 ff7514 }

	condition:
		7 of them and filesize <2049024
}