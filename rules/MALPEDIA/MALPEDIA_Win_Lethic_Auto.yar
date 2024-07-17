rule MALPEDIA_Win_Lethic_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "89881c0c-ddd2-5773-9144-03db6590b3cc"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lethic"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.lethic_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "3125ec39e54752d0947a08a6149f6c0dbb19d9ccd38ebef90b278b6227c3cc5c"
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
		$sequence_0 = { 837df400 7507 33c0 e9???????? 8b55f4 8b4218 }
		$sequence_1 = { 33c0 e9???????? 8b45fc 8b4d10 894804 }
		$sequence_2 = { 50 8b4dfc 83c108 51 8b55f4 }
		$sequence_3 = { 8b45fc 8b08 894dfc ebec 8b55fc }
		$sequence_4 = { eb42 6a10 8b55fc 83c208 52 }
		$sequence_5 = { ebec 8b55fc 8b45f4 8b08 890a 8b55fc }
		$sequence_6 = { 8945fc c745f801000000 837dfc00 7507 33c0 e9???????? 8b45fc }
		$sequence_7 = { 3b55f8 7411 8b45fc c60000 }
		$sequence_8 = { 8b08 890a 8b55fc 8b02 8945fc 8b4df4 51 }
		$sequence_9 = { eb42 6a10 8b55fc 83c208 52 8b45fc 8b4818 }

	condition:
		7 of them and filesize <81920
}