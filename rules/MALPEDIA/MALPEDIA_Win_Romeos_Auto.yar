
rule MALPEDIA_Win_Romeos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0156645c-05e4-5c43-9143-7d272fa7b808"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romeos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.romeos_auto.yar#L1-L178"
		license_url = "N/A"
		logic_hash = "c5549ec98f2ed02ef2ebca3bfe2dbd57b9e8c34679be2e9e834dd93b596fc1fe"
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
		$sequence_0 = { 750a 5e 33c0 5b 83c408 c20c00 8b06 }
		$sequence_1 = { bd30000000 33db 85ed 7e0e e8???????? 88441c18 43 }
		$sequence_2 = { 6a16 8d4c244c 6800200000 51 57 }
		$sequence_3 = { 83ec08 53 56 8b742418 8bd9 85f6 750a }
		$sequence_4 = { 5f 5e 5d 5b 81c438200000 c20400 }
		$sequence_5 = { 8b542408 668902 b001 c3 668b4801 40 51 }
		$sequence_6 = { 85db 751d 807c244802 0f85e0000000 8d542414 8d442448 }
		$sequence_7 = { 6a16 8d44244c 52 50 }
		$sequence_8 = { 68bb010000 8b39 50 ff15???????? 8b8e20030000 50 53 }
		$sequence_9 = { e8???????? 8bf0 eb02 33f6 53 6800040000 8d4c243c }
		$sequence_10 = { 50 8bce e8???????? 8d8c2490010000 51 }
		$sequence_11 = { 81c428010000 c3 5f 5e 5d 83c8ff 5b }
		$sequence_12 = { 8bf1 57 b940000000 33c0 8d7c2415 c644241400 c744240800000000 }
		$sequence_13 = { 895c2440 895c2434 895c2438 ff15???????? }
		$sequence_14 = { 8b442410 85c0 7408 66837c241400 7510 47 }
		$sequence_15 = { 8b3a eb0d 8b8e20030000 68bb010000 }

	condition:
		7 of them and filesize <294912
}