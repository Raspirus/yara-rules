rule MALPEDIA_Win_Atlas_Agent_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "31d9d19b-f3ba-501d-964d-67da428e9e82"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atlas_agent"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.atlas_agent_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "49564f12d410922863a80d6084c9c71952a7f941729a00c4d7e4e12f95d889bc"
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
		$sequence_0 = { 0fb60c0a 83e13c c1f902 03c1 }
		$sequence_1 = { 8bc1 99 b903000000 f7f9 c1e002 }
		$sequence_2 = { 4c8b8424c8000000 488b9424c0000000 488b8c2480000000 e8???????? 89442460 }
		$sequence_3 = { 4c8b8424e0000000 488b9424d8000000 488b4c2468 e8???????? }
		$sequence_4 = { 89857cffffff c645fc06 83bd7cffffff00 7417 }
		$sequence_5 = { 898584feffff 8b8584feffff 50 8d8dd4feffff }
		$sequence_6 = { 898588f8ffff 8b9588f8ffff 899584f8ffff c645fc07 }
		$sequence_7 = { 4c8b8424f0000000 488b942488000000 488b8c24e0000000 e8???????? }
		$sequence_8 = { 89857cffffff 83bd7cffffff1e 7302 eb05 }
		$sequence_9 = { 4c8b8424f8000000 488b942400010000 488d8c24f0030000 e8???????? }
		$sequence_10 = { 89857cffffff 8b8d18ffffff 894d80 83bd7cffffff00 }
		$sequence_11 = { 4c8b8c2408010000 4c8d05c2930400 ba40000000 488d4c2470 }
		$sequence_12 = { 89857cffffff 895580 8b4580 3b45dc }
		$sequence_13 = { 4c8b8c2408010000 4c8d442460 488b9424f8000000 488b8c24f0000000 }

	condition:
		7 of them and filesize <857088
}