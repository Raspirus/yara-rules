rule MALPEDIA_Win_Virut_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d1cda5ac-7426-54df-b118-5de8978eea9c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virut"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.virut_auto.yar#L1-L166"
		license_url = "N/A"
		logic_hash = "2bad431ccdf4fab7d1de984be24a8fafd07e087427bb72238bd9b56468720628"
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
		$sequence_0 = { 89442418 3bc3 0f8441020000 6801040000 8d8424fc050000 53 50 }
		$sequence_1 = { 33f6 8bca 83c107 3bcb 7e1b }
		$sequence_2 = { 0f8402010000 803f4d 0f85f9000000 807f015a }
		$sequence_3 = { 6a00 59 e30a 6a0a }
		$sequence_4 = { ff74241c 6a40 ff15???????? 8bf8 33c0 3bf3 }
		$sequence_5 = { 8bf0 3bf3 0f8e82000000 ff74240c 57 56 }
		$sequence_6 = { 51 6800040000 8d8c2404060000 51 89442428 }
		$sequence_7 = { 8bcb f3a6 61 7405 }
		$sequence_8 = { 8bd4 6a00 52 ff32 }
		$sequence_9 = { 33d2 8bcf 52 f6d9 52 83e103 6a40 }
		$sequence_10 = { 6800030084 51 51 56 }
		$sequence_11 = { 49 4e 45 54 2e44 4c }
		$sequence_12 = { 53 8d442444 50 8d8424e0020000 50 ffd6 }
		$sequence_13 = { eb49 395c240c 7449 33c0 395c240c 7e24 }
		$sequence_14 = { 6a10 59 f3ab 50 50 }
		$sequence_15 = { 66ab 8d4704 ab 32e4 ac }

	condition:
		7 of them and filesize <98304
}