
rule MALPEDIA_Win_Phoenix_Locker_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "34d54537-0c22-56ee-a952-e063e1672ba8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phoenix_locker"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.phoenix_locker_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "30c99eed67f01ec94c0d1a86e9de20b1f5e3b05899cb4448846bf96ce3ca2f7f"
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
		$sequence_0 = { 480fabc8 48ffc8 4180d05d 488d542420 488b01 66442bc4 }
		$sequence_1 = { b91d692dbc 4d0f45e7 4533c9 e8???????? 4c8b6c2438 4c8d442440 413bc7 }
		$sequence_2 = { 6681942400000000c64d 66c18c2400000000d9 66c184240000000074 e8???????? e2ac 1234ca 99 }
		$sequence_3 = { 4d8d8424b602a3ea 660fbeca 488bcb e9???????? e8???????? 8bd5 498d8c1cb602a3ea }
		$sequence_4 = { e9???????? ff15???????? 33c9 4180fa13 3bc1 0f8417000000 488b4c2468 }
		$sequence_5 = { 68d30f1c2f 4881842430000000bd5eeb17 66c1bc245800000025 4159 415f 4159 4159 }
		$sequence_6 = { 0f8539000000 8d4d39 664181d42122 f9 8d455b 4d63e0 }
		$sequence_7 = { 68d701373c 48818424080000003feaebff 55 c0e254 5a 5a c3 }
		$sequence_8 = { e8???????? 4881842418000000aa78f72a 488b7c2428 48c74424281256ce88 68d72a8642 48c1a42400000000ef 689b25ad02 }
		$sequence_9 = { e8???????? 4155 4151 9c 49b98059c32d64378851 e8???????? 4c0fbbea }

	condition:
		7 of them and filesize <3702784
}