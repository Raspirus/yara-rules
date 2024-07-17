
rule MALPEDIA_Win_Helauto_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8190d0b6-60e2-55b8-bbd3-4f8143a5c37c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.helauto"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.helauto_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "4d9d81740e3a201d5c095a9d2008fa9ef0381381c707cf34a732c2ace99e1c38"
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
		$sequence_0 = { 8b45d4 83c40c 898568ffffff 8b45d0 }
		$sequence_1 = { ff75ec ffd6 6830750000 eb48 }
		$sequence_2 = { 69c060ea0000 83c430 3d60ea0000 a3???????? }
		$sequence_3 = { 85c0 0f841f010000 8b3d???????? 6a05 8d85a8f3ffff 68???????? }
		$sequence_4 = { 59 50 8d8574ffffff 50 53 53 ff75fc }
		$sequence_5 = { 85c0 7508 53 ff15???????? 59 33c0 }
		$sequence_6 = { 50 ff15???????? 83c40c 85c0 0f8593000000 50 }
		$sequence_7 = { 68???????? 50 ff15???????? 83c40c 85c0 0f8593000000 }
		$sequence_8 = { 8d4608 50 68???????? 53 e8???????? 83c418 83feff }
		$sequence_9 = { 51 8d4df0 e8???????? 8365fc00 8d4df0 }

	condition:
		7 of them and filesize <57344
}