rule MALPEDIA_Win_Bolek_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "21f1a0ba-06a1-5668-aea4-333af031f0f6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bolek"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.bolek_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "28c372302adc63618e82259e643572bec2793a354bb442ed761054ecd6bf8112"
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
		$sequence_0 = { 894c2454 8bc7 8b8c24ac000000 8bdf 0facc808 33ed c1e318 }
		$sequence_1 = { 3b31 72e1 51 e8???????? 59 8bc7 5f }
		$sequence_2 = { 8bcd 0fa4c117 0bf9 c1e017 0bd8 8bcd 8b442460 }
		$sequence_3 = { 8d86f4000000 50 e8???????? 83c418 56 6880000000 ff750c }
		$sequence_4 = { dd442418 dc0d???????? dd1c24 68???????? 8b1d???????? 8d44242c 6a40 }
		$sequence_5 = { eb7a 3c03 0f85bf000000 53 6a01 8d442428 50 }
		$sequence_6 = { 85c9 746f 803900 746a 6a2c 51 890f }
		$sequence_7 = { e8???????? eb07 814f7c00040000 5f 5e 5d 5b }
		$sequence_8 = { 89448c20 41 83c304 ebd0 8bac2434030000 8b9c2430030000 85db }
		$sequence_9 = { 83e4f8 83ec68 8364242000 8364242400 8b450c c744241001234567 c744241489abcdef }

	condition:
		7 of them and filesize <892928
}