rule MALPEDIA_Win_Victorygate_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "992c5b2e-f41c-5577-b26b-d319a12e38e1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.victorygate"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.victorygate_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "ea38784ac607c199e10f70edff21cb5ba2438f5fbaa9d25c8260862ff3bec34e"
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
		$sequence_0 = { 7214 8b49fc 83c223 2bc1 83c0fc 83f81f 0f879a120000 }
		$sequence_1 = { 8bce c645fc08 e8???????? c645fc01 8b55e8 83fa10 7228 }
		$sequence_2 = { 8bf8 893b 897b04 03cf 33c0 894b08 eb03 }
		$sequence_3 = { ff15???????? 85c0 0f8593010000 ff75f8 8d8678020000 6a57 50 }
		$sequence_4 = { e9???????? 3b0d???????? 7501 c3 e9???????? 55 8bec }
		$sequence_5 = { 0f8537050000 ff75f8 8d8630020000 6a32 50 }
		$sequence_6 = { 85c0 7537 b901000000 f00fb10f 85c0 7533 817e340c2b0000 }
		$sequence_7 = { 8b4128 8b7124 8945b8 3bf0 7436 660f1f440000 8b06 }
		$sequence_8 = { 57 8b00 8945c4 663908 0f8548060000 8b703c 03f0 }
		$sequence_9 = { c745fc19000000 83ec18 8b4de0 8bc4 896584 c70000000000 c7401000000000 }

	condition:
		7 of them and filesize <1209344
}