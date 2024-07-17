
rule MALPEDIA_Win_Wininetloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1f5f1063-d131-51ec-8fa2-72e334bf0ad8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wininetloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.wininetloader_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "18fd24bb687ec61c125dfaa2108b7d0deaa39d2f9fd1538d0119b221d934fb42"
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
		$sequence_0 = { 7510 0fb611 0fb6c2 80fa28 7423 80fa29 741e }
		$sequence_1 = { 4c8bac2480000000 90 493bdf 74db 0fb633 498bcd 410fb61424 }
		$sequence_2 = { 48897c2460 4d8bc5 488b542438 488bc8 e8???????? 4b8d042e 4889442458 }
		$sequence_3 = { 90 488d5508 48837d2008 480f435508 488b4518 4c8d0c42 4c8d4508 }
		$sequence_4 = { e8???????? 3a03 7516 488bcf e8???????? 4c8b45f8 488b4df0 }
		$sequence_5 = { 4c8be0 4889442450 4885db 7427 488b03 488bcb 488b4010 }
		$sequence_6 = { 4c894d08 33db 448bf3 895c2470 49395910 752b 488d15b6ea1100 }
		$sequence_7 = { 3a8c2ab8a80e00 0f8585000000 488b03 48ffc2 8a08 48ffc0 488903 }
		$sequence_8 = { 488d1d48970500 807e5704 7704 488b5e48 48ffc7 803c3b00 75f7 }
		$sequence_9 = { eb21 48c74424200f000000 4c8d0d54fd0900 4533c0 418d500f 488d4c2430 e8???????? }

	condition:
		7 of them and filesize <2659328
}