rule MALPEDIA_Win_Unidentified_076_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c76f9b8e-5a48-5b08-ae0b-831af19ce579"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_076"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_076_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "afb3d60b25322ebd0dc1ef4a0c20812c54fa6c9c843b7734da080ace48ec2894"
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
		$sequence_0 = { 488b5370 488d4520 488bcb 4889442420 e8???????? 8bc8 eb7c }
		$sequence_1 = { 747b 8d5620 448bce 448bc5 33c9 ff97f8000000 48898748020000 }
		$sequence_2 = { 488bcf ff9080000000 33d2 33c9 4c63c0 85c0 7e29 }
		$sequence_3 = { 48894178 488b8f80000000 488b4618 48034f50 48898880000000 488b8f90000000 488b4618 }
		$sequence_4 = { 458d6502 448bc7 488bce 4489642428 89442420 e8???????? 85c0 }
		$sequence_5 = { 488d8d40150000 e8???????? 488d1587720000 488d8d14090000 8985d4000000 488d05c3130000 c7853001000000080000 }
		$sequence_6 = { 4533c9 488bcf 448d420c 48895c2420 e8???????? eb05 bb01000000 }
		$sequence_7 = { 7f0b 41b907000000 e9???????? 488b83c8000000 488b9360020000 488d8b5c060000 ff90f0070000 }
		$sequence_8 = { 89442420 e8???????? eb56 83f801 7529 8b8714120000 448b8f10120000 }
		$sequence_9 = { 415e 415c c3 817d0c08020000 7c05 458bcc eba2 }

	condition:
		7 of them and filesize <114688
}