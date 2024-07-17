
rule MALPEDIA_Win_Cryptomix_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9865a2c1-f352-5196-8a74-a585373e6231"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptomix"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cryptomix_auto.yar#L1-L173"
		license_url = "N/A"
		logic_hash = "2b59fc336b11257878a1c3e0c2e35ea57cb53b57126b62f006b040ede13bda6d"
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
		$sequence_0 = { c3 68f0767c2a 6a04 e8???????? 59 59 }
		$sequence_1 = { 02f8 0fb6cf 8d7601 0fb60439 8846ff 881439 33c9 }
		$sequence_2 = { e8???????? 59 eb03 8b5df0 ff75f8 e8???????? }
		$sequence_3 = { 7504 6a08 eb35 83f804 }
		$sequence_4 = { ff4d08 8b4dfc 8ad8 75cc 5f }
		$sequence_5 = { 59 59 ffd0 83f87a 7413 56 57 }
		$sequence_6 = { 56 683f000f00 56 56 56 53 57 }
		$sequence_7 = { ffd0 c3 686ea4ffa5 6a05 }
		$sequence_8 = { ffd6 85c0 0f856a010000 68???????? 8d85c4f9ffff }
		$sequence_9 = { 837d0c01 8bbdb8f9ffff a1???????? 68???????? }
		$sequence_10 = { 68???????? 57 ffd0 ff75fc e8???????? }
		$sequence_11 = { 8bf1 6a01 899584efffff 89b58cefffff 898588efffff ff15???????? 6808020000 }
		$sequence_12 = { 8d85c4f9ffff 50 ffd7 85c0 7460 68???????? }
		$sequence_13 = { 8b35???????? 68007d0000 6a40 c745f8e8030000 }
		$sequence_14 = { 6a00 6a00 ff15???????? 6896000000 ff15???????? 8b9d80efffff 8d8598f9ffff }
		$sequence_15 = { 68???????? 56 e8???????? 59 59 85c0 7759 }

	condition:
		7 of them and filesize <188416
}