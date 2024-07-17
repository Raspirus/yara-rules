
rule MALPEDIA_Win_Avaddon_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "63f23353-9bc4-58e9-928a-ae89a2672871"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avaddon"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.avaddon_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "a18db52df950b60c5b6d6008b561a4d13093802e02b6d570e4f6e8e4ed4f56e8"
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
		$sequence_0 = { 55 8bec 83e4f8 8b11 83ec14 0faf5104 53 }
		$sequence_1 = { 52 50 e8???????? 8bf0 8bfa 8b4508 03f3 }
		$sequence_2 = { 8d4dcc e9???????? 8d4d88 e9???????? 8d4db4 e9???????? 8d4de4 }
		$sequence_3 = { 8b4df0 e9???????? 8d4dbc e9???????? 8b542408 8d420c 8b4ac0 }
		$sequence_4 = { 57 56 e8???????? 83c408 85c0 7535 837e6402 }
		$sequence_5 = { 8bd0 e8???????? 8b5604 83c404 }
		$sequence_6 = { ff75b4 e8???????? 83c408 47 897dac 81fffe000000 0f8654feffff }
		$sequence_7 = { 8bc8 2bce 0fafcb 890a 83c204 8b4de4 41 }
		$sequence_8 = { 034b08 4e 8b4588 6a00 52 51 56 }
		$sequence_9 = { 8d4dd8 e8???????? c645fc0d 8b4f14 3b4f18 7437 c7411000000000 }

	condition:
		7 of them and filesize <2343936
}