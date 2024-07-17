rule MALPEDIA_Win_Eyservice_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e6b201c5-31f5-59a2-a52d-309e470fcb5a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eyservice"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.eyservice_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "a8d5ae517d0720536deb96b397532bb33ed4fe4db40da33e37b572e015c805c7"
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
		$sequence_0 = { c1f802 3bf0 72da eb22 8b0d???????? 2b0d???????? c1f902 }
		$sequence_1 = { 6a01 6a01 68???????? ffd6 83c410 8d542410 52 }
		$sequence_2 = { 83bef800000000 747c 8d4c2408 e8???????? a1???????? 8d4c2408 51 }
		$sequence_3 = { 6808020000 8d8e34020000 51 e8???????? 85c0 7c1e }
		$sequence_4 = { 83c404 8bc8 e8???????? 8bf0 8bce e8???????? 8b4f10 }
		$sequence_5 = { e8???????? b901000000 66894f08 5f 5e 5d 8d410d }
		$sequence_6 = { 68???????? 8d542418 52 ff15???????? 85c0 754f 88442414 }
		$sequence_7 = { 50 03f7 56 e8???????? 8b4c2420 83c410 5f }
		$sequence_8 = { a3???????? e8???????? 6a06 68???????? 56 a3???????? }
		$sequence_9 = { 85c0 7459 66837d005c 7452 66837c24145c 754a }

	condition:
		7 of them and filesize <452608
}