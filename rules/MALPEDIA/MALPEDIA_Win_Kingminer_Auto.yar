
rule MALPEDIA_Win_Kingminer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "13b82737-eb1a-51ab-9795-8340f262e7e5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kingminer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kingminer_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "f79d58fb6043de2ccd7faac7ea9ed3b2513556edb2a1cd9df8f496a155aebade"
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
		$sequence_0 = { a1???????? 885c30fe a1???????? 0fb64c30f9 884c30fc }
		$sequence_1 = { ff15???????? 6a01 ff15???????? 6a00 ff15???????? 8b4508 }
		$sequence_2 = { 83c40c 807c30ff62 8d4c30ff 0f8599010000 }
		$sequence_3 = { ff15???????? 6a00 ff15???????? 8b80c0000000 85c0 7422 }
		$sequence_4 = { 6a00 ff15???????? 6a00 ff15???????? 6a01 ff15???????? 6a00 }
		$sequence_5 = { 3bf0 741e 68c1000000 ff15???????? 5b }
		$sequence_6 = { ff15???????? a1???????? 50 ffd7 ff15???????? 6a01 ff15???????? }
		$sequence_7 = { 6a04 6800100000 51 52 ffd0 83c414 85c0 }
		$sequence_8 = { 8d4dec 51 8d580c 56 8bc7 c745ec89480489 }
		$sequence_9 = { 8b95d0feffff 2b4234 7419 83b9a000000000 7466 50 }

	condition:
		7 of them and filesize <165888
}