rule MALPEDIA_Win_Blackbasta_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5c8e56ab-6cbd-5deb-8276-9c7c1c51570f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbasta"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.blackbasta_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "7b0b80b4e818e69a7ef8a8ed63d1384307760adc672033eb9b7389cd6b55895b"
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
		$sequence_0 = { ff7590 8bcf e8???????? 84c0 751f 384704 7507 }
		$sequence_1 = { 89b574ffffff 894588 89458c e8???????? 84c0 755d 384304 }
		$sequence_2 = { 5b 8b4df4 64890d00000000 8d656c 5d c3 8d4d30 }
		$sequence_3 = { e8???????? 83c404 85c0 0f849d010000 8d5823 83e3e0 8943fc }
		$sequence_4 = { c745e000000000 c745e40f000000 c645d000 c745fc00000000 ff734c e8???????? 83c404 }
		$sequence_5 = { b867666666 c645e800 f7ea c1fa05 8bc2 c1e81f 03c2 }
		$sequence_6 = { 85f6 7462 8b7d28 3bf7 7416 0f1f440000 8bce }
		$sequence_7 = { 56 e8???????? 83463008 83c410 0fb6c3 81c500020000 8b5c2474 }
		$sequence_8 = { 8d4dc0 e8???????? 837e1401 741a 837dec01 740d 8d45d8 }
		$sequence_9 = { 83c410 8bce 50 68???????? e8???????? 8bf0 c78574ffffff00000000 }

	condition:
		7 of them and filesize <1758208
}