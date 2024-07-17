
rule MALPEDIA_Win_Graphican_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a2f03fc9-ee25-5fcd-896d-9bb49120884f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphican"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.graphican_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "a4c9c330e82d4ca3a447533684cd37026bb60c45e700ff39380301b043754c33"
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
		$sequence_0 = { 8d5f07 83e3f8 03d3 3b10 7619 8b06 3bc3 }
		$sequence_1 = { 3c65 7408 3c45 0f8570010000 47 807def00 897dc0 }
		$sequence_2 = { 56 57 8bf1 8bfa 85db 7517 68a8010000 }
		$sequence_3 = { 53 8bf0 6a00 56 e8???????? a1???????? }
		$sequence_4 = { 8d0c89 8d4c48d0 8a07 42 3c30 7dd4 894de8 }
		$sequence_5 = { 68???????? 68???????? e8???????? 83c40c 8b4ddc c7461810000000 894e1c }
		$sequence_6 = { 8d85e8edffff 6a00 50 e8???????? 83c40c 68???????? }
		$sequence_7 = { 68???????? 68???????? e8???????? 83c40c 8b5624 2b5620 }
		$sequence_8 = { 8d8dc4efffff 51 50 ffd2 8bb5c4efffff 33ff }
		$sequence_9 = { 8bd8 e8???????? 8d4311 83c404 }

	condition:
		7 of them and filesize <362496
}