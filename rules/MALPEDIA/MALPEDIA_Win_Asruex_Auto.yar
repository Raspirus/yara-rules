rule MALPEDIA_Win_Asruex_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "899abd0f-c835-5f70-819c-92570cc9b462"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asruex"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.asruex_auto.yar#L1-L112"
		license_url = "N/A"
		logic_hash = "a14db0e4e44f1156fe16afe843345aa29b9b1f1eb3cc060b10e0bcdf06eb97d4"
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
		$sequence_0 = { 85c0 740e 85ed 740a }
		$sequence_1 = { 7408 3c0d 7404 3c0a 7516 }
		$sequence_2 = { 83f801 740e 83f803 7409 83f802 }
		$sequence_3 = { ff15???????? 85c0 7407 3d14270000 }
		$sequence_4 = { 740c 3c09 7408 3c0d 7404 3c0a 7516 }
		$sequence_5 = { 7404 3c58 7505 bb01000000 }
		$sequence_6 = { 3c09 7408 3c0d 7404 3c0a 7516 }
		$sequence_7 = { 3c78 7404 3c58 7505 bb01000000 }
		$sequence_8 = { 3c0d 7404 3c0a 7516 }
		$sequence_9 = { e8???????? 83f8ff 7407 3d0000a000 }

	condition:
		7 of them and filesize <1564672
}