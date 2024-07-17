rule MALPEDIA_Win_Ketrican_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "03c6cec7-6d12-51a2-b1a9-8239f834bf9b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ketrican"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ketrican_auto.yar#L1-L227"
		license_url = "N/A"
		logic_hash = "c6a0e9c9ef6d7c9c9c9505df3e47863f2b32a94701647f7dc167a7885087d327"
		score = 75
		quality = 71
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
		$sequence_0 = { 8965f0 33db 895dfc 33c0 }
		$sequence_1 = { 7417 6a0a 6a1f 68???????? }
		$sequence_2 = { e8???????? 83c010 8906 c3 56 }
		$sequence_3 = { 8bd1 e8???????? 5f 5e c3 55 8bec }
		$sequence_4 = { 8b06 5d c20400 55 8bec 8b4508 894508 }
		$sequence_5 = { 8bc1 8945f0 834dfcff e8???????? }
		$sequence_6 = { 8901 5b 5d c20800 680e000780 e8???????? cc }
		$sequence_7 = { 680e000780 e8???????? cc 8b06 83e810 8b08 }
		$sequence_8 = { 48 7445 48 743a 48 }
		$sequence_9 = { 884603 83c604 8345f804 8b45f8 5f }
		$sequence_10 = { 58 668945d8 6a72 58 }
		$sequence_11 = { 6a00 8d85f1fbffff 50 e8???????? 83c40c 6800040000 }
		$sequence_12 = { ff7508 53 53 ffd6 5f 5e }
		$sequence_13 = { 740a 48 754a e8???????? }
		$sequence_14 = { 83c002 663bd3 75f5 2bc1 d1f8 8d7001 6800080200 }
		$sequence_15 = { e8???????? 8b8a8c2f0000 33c8 e8???????? b8???????? }
		$sequence_16 = { ff15???????? 68???????? c705????????98824100 a3???????? }
		$sequence_17 = { 8d420c 8b4ae8 33c8 e8???????? 8b8a4c010000 }
		$sequence_18 = { 33c8 e8???????? 8b8ae8080000 33c8 e8???????? }
		$sequence_19 = { 8d4dd0 e9???????? 8d4de0 e9???????? 8d4db8 e9???????? 8d4ddc }
		$sequence_20 = { b8???????? e9???????? 8b542408 8d420c 8b8aa4feffff 33c8 }
		$sequence_21 = { c705????????98824100 a3???????? c605????????00 e8???????? 59 }
		$sequence_22 = { 8b8a54ffffff 33c8 e8???????? 8b8adc090000 33c8 e8???????? }

	condition:
		7 of them and filesize <1449984
}