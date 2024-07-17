
rule MALPEDIA_Win_Bbsrat_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1bf7f125-76bf-51d8-8714-b1f4351a2fc5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bbsrat"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bbsrat_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "d09c46b568c20e6cc1497fd9b00b10dfec3bd249a240c9cb1f2d27667bcf264d"
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
		$sequence_0 = { e8???????? 8b7c2410 81c610020000 d1eb 45 85db 75b5 }
		$sequence_1 = { 83c8ff 898e44020000 899648020000 57 894308 894304 8903 }
		$sequence_2 = { 03c0 03c0 50 898374010000 e8???????? 8b8b74010000 83c404 }
		$sequence_3 = { 8be5 5d c20c00 51 e8???????? 5e 5b }
		$sequence_4 = { ffd7 895e24 8b461c 3bc3 741a 53 50 }
		$sequence_5 = { eb21 83f805 7529 8d8c243c010000 51 8d842448030000 e8???????? }
		$sequence_6 = { ff15???????? 8bf8 6a10 56 6861001100 }
		$sequence_7 = { 52 8d6e18 55 8d7e0c 57 894608 e8???????? }
		$sequence_8 = { ffd7 a3???????? 85c0 7412 8d4c2408 51 }
		$sequence_9 = { 6a00 52 8bd8 56 895c2428 ff15???????? 8b4f0c }

	condition:
		7 of them and filesize <434176
}