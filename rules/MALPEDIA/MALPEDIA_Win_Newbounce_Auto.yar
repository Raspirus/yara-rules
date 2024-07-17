rule MALPEDIA_Win_Newbounce_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "70b5f47a-ee55-5897-8fcd-06a813c41881"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newbounce"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.newbounce_auto.yar#L1-L151"
		license_url = "N/A"
		logic_hash = "53d4154f041c8f5d8c7be0de086b650af8bff8de758570421d79234a0be341f3"
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
		$sequence_0 = { 83e00f 7e05 2bf0 83c610 }
		$sequence_1 = { ff15???????? 85c0 0f844b010000 ba28000000 }
		$sequence_2 = { ff15???????? 85c0 0f8437020000 8b4c2428 }
		$sequence_3 = { ff15???????? 85c0 0f8436020000 4889bc2428010000 c784242001000022000000 c784241801000073252000 c78424100100006b2d2000 }
		$sequence_4 = { 75f5 49ffc8 75eb 488d8104020000 }
		$sequence_5 = { e8???????? cc b201 488bcf e8???????? 4c8d1d8f920100 488d5547 }
		$sequence_6 = { 75f2 ebe3 488d154ac20100 498bcc 4d8bc7 }
		$sequence_7 = { 75f5 49ffc9 75e8 488d8e54030000 }
		$sequence_8 = { 81e3c0000000 0bf3 c1ee06 0b14b5b0876300 }
		$sequence_9 = { 81e300000600 c1ea14 8b1495b0896300 81e6000f0000 }
		$sequence_10 = { 81e300e00100 0bf3 c1ee0d 0b0cb5b0886300 }
		$sequence_11 = { 81e2ff000000 8b0c8d48436300 8b1c9d48476300 33cb 8b1c85484b6300 2bcb }
		$sequence_12 = { 81e2ff000000 c1e808 c1e208 53 }
		$sequence_13 = { 81e3001e0000 8bef 81e50000e001 0bf5 c1ee15 8b34b5b08d6300 }
		$sequence_14 = { 81e3001e0000 8bd5 81e280010000 0bda 8b14b5b08d6300 }

	condition:
		7 of them and filesize <8637440
}