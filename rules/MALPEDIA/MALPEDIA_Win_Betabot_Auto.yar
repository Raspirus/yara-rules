rule MALPEDIA_Win_Betabot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "66328af7-8459-5b35-88d1-7e63b7ee5eb4"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.betabot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.betabot_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "51b7b8c3c50a8d4a628d1b4c5d49a49007142cba41644cf909b7bfdb76b9cbc5"
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
		$sequence_0 = { 8d85e4f7ffff 89bde8f7ffff 50 33ff 56 47 56 }
		$sequence_1 = { 8d44244c 50 ff15???????? 8d442448 50 e8???????? 8d442448 }
		$sequence_2 = { 32c0 e9???????? 6a40 5e e8???????? a3???????? }
		$sequence_3 = { 884617 2407 80fa40 7413 80fa80 7404 }
		$sequence_4 = { 85c0 7503 6afd 58 5f 5e 5b }
		$sequence_5 = { c20400 55 8bec 83ec18 53 56 8365f800 }
		$sequence_6 = { a1???????? 85c0 740b 8d4dfc 51 ff7508 ffd0 }
		$sequence_7 = { bbb0040000 85f6 7433 a1???????? 48 50 }
		$sequence_8 = { 8a460a 3cb9 740c 3c33 7408 c70302000000 eb34 }
		$sequence_9 = { 7470 66397508 746a 6a02 59 ff7508 66894de8 }

	condition:
		7 of them and filesize <835584
}