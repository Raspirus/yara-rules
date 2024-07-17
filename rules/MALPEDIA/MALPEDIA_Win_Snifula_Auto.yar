
rule MALPEDIA_Win_Snifula_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3dffa8bc-fef5-5d9b-860e-b2ad6113d3e0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snifula"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.snifula_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "5394c0842b5f05f382e3a7b0318fd2397f5c79fe7938989019ff20c4e8348941"
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
		$sequence_0 = { 53 ff35???????? ffd7 6800040000 53 ff35???????? }
		$sequence_1 = { 53 6a00 ff35???????? ff15???????? b8???????? 83c9ff }
		$sequence_2 = { 6a00 ff35???????? 8945fc ff15???????? 8bf8 85ff }
		$sequence_3 = { a1???????? 85c0 75ef 53 57 bb???????? }
		$sequence_4 = { ff15???????? 8bf8 83ffff 747f 53 8d450c 50 }
		$sequence_5 = { e8???????? 85c0 740c 81386368756e 7504 834e1002 8bc6 }
		$sequence_6 = { c1e802 25ff000000 8d44c72c 8b18 3bd8 7432 }
		$sequence_7 = { 83f803 7533 ff7304 8bc7 ff750c e8???????? 8b4724 }
		$sequence_8 = { 68???????? 56 ff15???????? 83c414 68???????? 56 }
		$sequence_9 = { 53 50 889c243c010000 e8???????? a1???????? 83c43c 895c2430 }

	condition:
		7 of them and filesize <188416
}