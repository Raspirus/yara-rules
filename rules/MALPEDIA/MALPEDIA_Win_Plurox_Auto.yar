rule MALPEDIA_Win_Plurox_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6592f7da-a1c0-54df-8b9b-d6d4f0de3577"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plurox"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.plurox_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "2767330918862f71924876620bde24f2504b741e0c74e8fbd24789f747d1fbb9"
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
		$sequence_0 = { 90 f9 0925???????? 0000 }
		$sequence_1 = { 1a6e00 0000 94 624a8b 0416 }
		$sequence_2 = { 6f b804000000 4e 4f b84e4f3dd9 }
		$sequence_3 = { 94 f8 21480e 2a15???????? 6f b804000000 }
		$sequence_4 = { e9???????? e408 6873d30808 94 e519 e8???????? 0000 }
		$sequence_5 = { 8918 43 0416 0a20 0816 ec bbf2000000 }
		$sequence_6 = { 8a00 46 0c83 47 }
		$sequence_7 = { 624a8b 0416 128bc606091a f6870f1a000000 e10d }
		$sequence_8 = { 07 f3cf 6b0000 0025???????? 7171 6805245f07 40 }
		$sequence_9 = { 64841a 6c 2432 3449 }

	condition:
		7 of them and filesize <475136
}