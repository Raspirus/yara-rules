
rule MALPEDIA_Win_Unidentified_080_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b4f490ab-c91a-5e77-9e61-88b48864f732"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_080"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_080_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "a554ba61b72496370ffd16dee0c3f2b6444ec6fc0c35b79b5428032562bbd4cc"
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
		$sequence_0 = { 51 53 8bd8 837b2c00 56 7571 8b4324 }
		$sequence_1 = { 0bf2 89701c 83c020 83c120 ff8d74ffffff 0f8560feffff 8b8570ffffff }
		$sequence_2 = { 8b4508 8b4808 8b500c 2bd1 894dfc 3bd3 7277 }
		$sequence_3 = { 3bd6 7312 8b03 833c9000 8d0490 7402 }
		$sequence_4 = { 8dbd40ffffff e8???????? 8bb53cffffff 83c620 c645fc0f 8b06 33ff }
		$sequence_5 = { 83e73f 0b0cbdb8840210 83e03f 0b0c85b8860210 8b42f4 33c6 8bf8 }
		$sequence_6 = { 8bec 83ec10 53 8bd8 ff4320 56 33f6 }
		$sequence_7 = { 8bf0 83feff 7509 c68568ffffff0b eb66 8b4dbc }
		$sequence_8 = { 57 50 8d45f4 64a300000000 33ff 33f6 }
		$sequence_9 = { 8b4e30 8d5508 52 8b562c 50 51 52 }

	condition:
		7 of them and filesize <392192
}