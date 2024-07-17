
rule MALPEDIA_Win_Webc2_Yahoo_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "63230a4f-7913-5b93-bb9a-30d89db03d73"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_yahoo"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.webc2_yahoo_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "f89dfba6353885aa09b69faf5df0db1655d3acae8a14a8bbfd9acb6fd6fd17df"
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
		$sequence_0 = { 59 7513 ff15???????? 8986a0841e00 }
		$sequence_1 = { 56 ff15???????? 802000 56 e8???????? }
		$sequence_2 = { 53 50 50 53 ff750c ff15???????? 57 }
		$sequence_3 = { 39be9c841e00 59 7513 ff15???????? 8986a0841e00 33c0 }
		$sequence_4 = { c745fc01000000 aa e8???????? 59 8d85f4d7ffff 50 8d45f8 }
		$sequence_5 = { 50 8d45f8 50 8d85f4afffff }
		$sequence_6 = { 8b7518 83c414 8d85fcd7ffff 8bcb }
		$sequence_7 = { 8b4d08 e8???????? 85c0 53 }
		$sequence_8 = { 59 50 ff75f8 ff75fc ffb69c841e00 ff15???????? }
		$sequence_9 = { 8d85c8fcffff 68???????? 50 e8???????? 83c410 85c0 7466 }

	condition:
		7 of them and filesize <8060928
}