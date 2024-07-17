
rule MALPEDIA_Win_Devopt_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b2799a63-9237-56b1-b622-1d4cf3bf7ea8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.devopt"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.devopt_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "f040e8bf75c02b10fb9ecd2b3e85bb747221bae38ed54254a620b66ea3085268"
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
		$sequence_0 = { eb42 8b45fc f7402810000000 7402 eb34 8b45fc 80b8a900000000 }
		$sequence_1 = { eb11 3b5df0 7e02 eba3 8d7600 c745f0ffffffff 8b45f0 }
		$sequence_2 = { eb0b 8b45fc 8b4034 8945d4 eb25 8b45d0 83e00f }
		$sequence_3 = { ff9240040000 84c0 7502 eb0b 8b55f8 8b45fc e8???????? }
		$sequence_4 = { e8???????? 8b45f4 ba???????? 8955e8 8945ec 8d55e8 31c0 }
		$sequence_5 = { 8b4240 8b55f4 8b4a40 8b11 ff5268 8945f0 89d7 }
		$sequence_6 = { ff93a8020000 8b45d4 8d40fc 50 8b45d0 8d48fc 8b45f8 }
		$sequence_7 = { 8d6424e0 53 8945f4 8955fc 894df8 837dfc00 7e02 }
		$sequence_8 = { ff75f0 ff75fc e8???????? 31d2 58 83c40c 648902 }
		$sequence_9 = { eb1e 8b45f8 a9ffffffff 7402 eb12 8b45f4 e8???????? }

	condition:
		7 of them and filesize <4645888
}