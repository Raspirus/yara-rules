rule MALPEDIA_Win_Unidentified_089_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f61e4a77-808b-5e07-801b-03e57ce838b5"
		date = "2023-07-11"
		modified = "2023-07-15"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_089"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_089_auto.yar#L1-L98"
		license_url = "N/A"
		logic_hash = "f9666eb88fbd91e0eb2e4b4c8812230b36d73d66192fed407aecfaa8f0ed362a"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 889dd4feffff 899d84feffff 898588feffff 889d74feffff 33c0 }
		$sequence_1 = { 8b4508 e8???????? c20c00 e8???????? cc 6a30 }
		$sequence_2 = { f2e9e3000000 55 8bec eb0d ff7508 e8???????? }
		$sequence_3 = { 83f904 0f8582000000 8b75d0 8bfb }
		$sequence_4 = { eb0f ff7634 57 ff562c }
		$sequence_5 = { 88041e 880c1f 0fb6041e 8b4dfc 03c2 8b550c }
		$sequence_6 = { 3dffffff7f 0f87a2000000 03c0 3d00100000 7227 }
		$sequence_7 = { 56 6a01 8d4dec 8975d8 }

	condition:
		7 of them and filesize <389120
}