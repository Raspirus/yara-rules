
rule MALPEDIA_Win_Lowzero_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ad1f4f71-db5d-51c4-9bc5-e40c45051891"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowzero"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lowzero_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "bfaa131f289b03263fe3207c7e09eedb0c528831bcdb16b693a70fc486a7a935"
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
		$sequence_0 = { 0fb617 47 83fa20 0f83e2000000 42 8d0432 3bc1 }
		$sequence_1 = { 57 8b423c 8b55f4 03c6 }
		$sequence_2 = { 2bce 894df0 8d9b00000000 8d1c31 ff7734 85c0 }
		$sequence_3 = { 7439 03c3 837f1400 7425 }
		$sequence_4 = { 47 2bc8 8d4602 03c3 3b450c }
		$sequence_5 = { 8b4d0c 3b7dfc 0f8255feffff 2b7508 5f 8bc6 5e }
		$sequence_6 = { 8bce 83e21f c1eb05 c1e208 2bca 49 83fb07 }
		$sequence_7 = { 83ec30 53 56 8bd9 8955f4 33f6 895dfc }
		$sequence_8 = { 46 47 e9???????? 8bda 8bce 83e21f }
		$sequence_9 = { e8???????? 5f 5e 5b c70007000000 33c0 8be5 }

	condition:
		7 of them and filesize <433152
}