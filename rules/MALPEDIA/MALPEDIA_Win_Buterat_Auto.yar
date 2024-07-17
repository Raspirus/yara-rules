
rule MALPEDIA_Win_Buterat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3e97b50a-971b-5a6b-945e-3e34fedb231a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buterat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.buterat_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "eb64ab06f54c3ecee14053c6efd01e298ad3b6ab4366443760576f0899003a4d"
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
		$sequence_0 = { 56 8d4dfc 51 57 50 53 }
		$sequence_1 = { 750a 56 6a07 e8???????? 59 59 ff750c }
		$sequence_2 = { ff15???????? 8b5d75 53 33c0 e8???????? 85c0 59 }
		$sequence_3 = { 56 57 33f6 e8???????? 85c0 59 0f868b000000 }
		$sequence_4 = { 750b e8???????? 99 f77dfc 8bda 837d6806 }
		$sequence_5 = { 8d8564dfffff 50 8bc3 e8???????? 83c40c ff75f4 ffd7 }
		$sequence_6 = { 8bec b800100000 e8???????? 8b4d08 }
		$sequence_7 = { e8???????? 83c40c 85c0 0f8424010000 68???????? 53 68???????? }
		$sequence_8 = { 41 41 47 3b7d0c 72cd 5b 33c0 }
		$sequence_9 = { 33db 385d1c 56 57 895df0 750d 8a4518 }

	condition:
		7 of them and filesize <278528
}