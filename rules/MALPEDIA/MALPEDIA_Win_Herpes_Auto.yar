
rule MALPEDIA_Win_Herpes_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "81a5deba-39e3-5a1f-937c-6696c1e1bbb2"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.herpes"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.herpes_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "e0891dbd163cc34c7d236958d6844c054a085f2a34f7c0d3c53aa2f138d5b650"
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
		$sequence_0 = { 7303 8d4570 ffb580000000 50 8b45f0 03c7 }
		$sequence_1 = { 8d9424380d0000 52 ffd6 eb30 6a38 8d4c241c 51 }
		$sequence_2 = { 68???????? eb05 68???????? 56 ffd7 bb05000000 399d64ffffff }
		$sequence_3 = { 68???????? 89869c010000 ffb604020000 ffd7 68???????? }
		$sequence_4 = { 64a300000000 b80f000000 33ff 8985e4feffff 89bde0feffff }
		$sequence_5 = { 57 ff15???????? 5f 8b4dfc 33cd e8???????? }
		$sequence_6 = { ff15???????? 85c0 742a 8b959cfdffff 52 e8???????? }
		$sequence_7 = { 39bdd4fcffff 7302 8bc3 83ec1c 8bf4 }
		$sequence_8 = { 52 ffd6 68???????? 8d858ffeffff 50 }
		$sequence_9 = { 52 6a00 89bde0fcffff ff15???????? 85c0 745e 8d85e4fcffff }

	condition:
		7 of them and filesize <319488
}