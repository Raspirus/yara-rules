rule MALPEDIA_Win_Hunter_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a2ce8975-358a-5feb-855e-0c18799189f7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hunter"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.hunter_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "4840112788d43f80efa44bf4553c38cceb240b146b43c82ea7ba535d388455f9"
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
		$sequence_0 = { 8d4323 03c8 8d83b5000000 038d3cffffff 03c8 8d83ae000000 03ce }
		$sequence_1 = { 8b5f08 8b440104 8945f0 8b13 8bc8 e8???????? 85c0 }
		$sequence_2 = { 8d4b38 0faf4dbc 898d34fdffff 8b8d1cffffff 0fafce 8d7375 898d8cfeffff }
		$sequence_3 = { 8bf9 6b1f14 8b743b0c eb38 0fbf0475080f4700 83f8c2 7433 }
		$sequence_4 = { 8b4c2440 6aff e8???????? 59 8b4c2448 33c0 89442424 }
		$sequence_5 = { 53 6a68 5a e8???????? 83c40c b208 8bce }
		$sequence_6 = { 8b4630 8b14b8 85d2 7405 e8???????? b980000000 e8???????? }
		$sequence_7 = { c3 51 56 57 8bf1 33c0 8b7e1c }
		$sequence_8 = { 8b4614 89442418 85c0 750c 385c2431 7506 885c2430 }
		$sequence_9 = { 8d8d04f8ffff e9???????? 8d8d1cf8ffff e9???????? 8d8de0feffff e9???????? 8d8d34f8ffff }

	condition:
		7 of them and filesize <1056768
}