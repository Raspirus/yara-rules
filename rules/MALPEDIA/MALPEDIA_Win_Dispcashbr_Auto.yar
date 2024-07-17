
rule MALPEDIA_Win_Dispcashbr_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "02a73395-ac12-50d4-b2ec-e868c4b1a459"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dispcashbr"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dispcashbr_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "60c8be22bea8462dd56c514e62576b626445f5aa18aea505cf9cb5c5983fb848"
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
		$sequence_0 = { e8???????? 83ec08 c7442408ceffffff c7442404???????? }
		$sequence_1 = { e8???????? 83ec08 c7442408eaffffff c7442404???????? }
		$sequence_2 = { e8???????? 83ec08 c7442408ceffffff c7442404???????? a1???????? 83c020 }
		$sequence_3 = { a1???????? 83c020 890424 e8???????? eb45 c70424f5ffffff e8???????? }
		$sequence_4 = { 83ec08 c7442408f2ffffff c7442404???????? a1???????? 83c020 890424 e8???????? }
		$sequence_5 = { 83ec08 c7442408d9ffffff c7442404???????? a1???????? 83c020 890424 }
		$sequence_6 = { 890424 e8???????? 83ec08 c7442408d7ffffff }
		$sequence_7 = { 890424 e8???????? 83ec08 c7442408c9ffffff c7442404???????? }
		$sequence_8 = { 83ec04 c744240404000000 890424 e8???????? 83ec08 c7442408f2ffffff c7442404???????? }
		$sequence_9 = { c70424f5ffffff e8???????? 83ec04 c744240404000000 }

	condition:
		7 of them and filesize <123904
}