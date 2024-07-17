rule MALPEDIA_Win_Nosu_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d0493836-076e-53ac-80d2-093749a42975"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nosu"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nosu_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "8ab8c6afe29bf167cf16b426bd8eca0dcd4e462cdef53cd757a920fd1f6ec318"
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
		$sequence_0 = { 50 8d4730 50 ff15???????? 03c0 8d5730 50 }
		$sequence_1 = { 399628040000 7438 399648010000 7430 3996b8020000 7428 8b8e48060000 }
		$sequence_2 = { 8bcf 8938 e8???????? 894500 85c0 }
		$sequence_3 = { e8???????? 59 85c0 7444 8b7c2410 bd???????? 55 }
		$sequence_4 = { 0f45cf 03ce 84c0 8b4508 51 ff742420 0f45d7 }
		$sequence_5 = { 7462 803b22 0f85d4010000 8d470c 50 8d5708 8d4c2418 }
		$sequence_6 = { 53 50 53 a5 8d942440080000 53 53 }
		$sequence_7 = { 8b442434 59 c60004 8b442430 c640010e }
		$sequence_8 = { 50 8d8e280a0000 e8???????? 59 8d442468 50 8d442424 }
		$sequence_9 = { 8d96a8000000 8d4e48 e8???????? 59 59 84c0 742c }

	condition:
		7 of them and filesize <513024
}