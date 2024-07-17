rule MALPEDIA_Win_Hermeticwizard_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "726bd88f-010b-5502-8637-f9d7bbeebd06"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hermeticwizard"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.hermeticwizard_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "42607a1b485bdd595d314b574245aeda955efc5b6dd3f18356065a03173a4530"
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
		$sequence_0 = { 8b4608 3b4208 eb31 83f803 7531 8d4a04 8d4604 }
		$sequence_1 = { 33c9 66897dca 6800080000 50 }
		$sequence_2 = { 8b35???????? ffd6 ff75e8 ffd6 5e 8b4508 5f }
		$sequence_3 = { 6bc930 53 8b5d10 8b0485c0dd0110 56 }
		$sequence_4 = { 6689854cffffff 6689854effffff 66898554ffffff 6689855effffff 66898d58ffffff 66898d5affffff 59 }
		$sequence_5 = { 8d4608 50 8d4908 e8???????? }
		$sequence_6 = { 6a02 58 668945e8 8b4104 }
		$sequence_7 = { c3 837d08ff 0f8401070000 e9???????? e9???????? 55 8bec }
		$sequence_8 = { ff15???????? 83f87a 7567 ff75fc 6a08 ff15???????? 50 }
		$sequence_9 = { ff15???????? 85c0 7504 b001 eb3a 57 56 }

	condition:
		7 of them and filesize <263168
}