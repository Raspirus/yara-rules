
rule MALPEDIA_Win_Donot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "38387986-3cf2-52ef-b35f-48e7a3ada73a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.donot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.donot_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "856eb217efb67c7a23eb4ad0af50dccbe8bb723a98d81632999df9a793bf3e4e"
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
		$sequence_0 = { 8b04c580b80310 5d c3 33c0 }
		$sequence_1 = { c7461400000000 0f1106 f30f7e45e4 660fd64610 c745e400000000 c745e80f000000 85d2 }
		$sequence_2 = { 03d3 d1fa 8d4102 894738 8b4710 8918 8b4720 }
		$sequence_3 = { e8???????? 8b15???????? b910000000 2bd6 8a0432 8d7601 3046ff }
		$sequence_4 = { 7361 8bc6 8bde 83e03f c1fb06 6bc838 8b049d187b0410 }
		$sequence_5 = { c645fc02 8d4dbc e8???????? 8bf8 83c404 3bf7 7465 }
		$sequence_6 = { 0f438540ffffff 50 ff15???????? c645fc1b 8b559c 83fa10 722c }
		$sequence_7 = { c6861002000000 8b8e0c020000 83f910 722f 8b86f8010000 41 81f900100000 }
		$sequence_8 = { c685bcedffff00 8d5101 8a01 41 84c0 75f9 }
		$sequence_9 = { c6863801000000 8b8e34010000 83f910 722f 8b8620010000 41 81f900100000 }

	condition:
		7 of them and filesize <626688
}