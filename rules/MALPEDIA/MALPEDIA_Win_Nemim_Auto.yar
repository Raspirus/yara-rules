
rule MALPEDIA_Win_Nemim_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7264494b-d73b-5298-a829-f60e4932364f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemim"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nemim_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "0e5cb332d550079bcd770b6c5ca18dad9c60646bca1f9092ed4ed3564e5ea600"
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
		$sequence_0 = { a1???????? c1e002 89b48050744300 8b0d???????? 893d???????? 890d???????? }
		$sequence_1 = { eb3b a1???????? 68???????? 50 e8???????? 83c408 }
		$sequence_2 = { 5e 5b c9 c20400 8bc1 c700???????? c3 }
		$sequence_3 = { 5e 5d b801000000 5b 81c4bc000000 c3 }
		$sequence_4 = { 8d44240c 55 50 56 c744241828010000 e8???????? 85c0 }
		$sequence_5 = { 51 e8???????? 8dbc24600a0000 83c9ff 33c0 }
		$sequence_6 = { 8b16 c1ea08 885001 8b0e c1e910 }
		$sequence_7 = { 52 e8???????? 8b4c2440 8944244c b801000000 }
		$sequence_8 = { 83fe10 7cde c605????????00 b90b000000 be???????? 8dbc2410010000 }
		$sequence_9 = { 8844244c e8???????? 68???????? e8???????? 68???????? 8bf0 }

	condition:
		7 of them and filesize <499712
}