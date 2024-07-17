
rule MALPEDIA_Win_Laturo_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a099051d-06cc-5747-80aa-ce74001854da"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.laturo"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.laturo_auto.yar#L1-L179"
		license_url = "N/A"
		logic_hash = "5c5686ac498628ddacc2bb584f3ee57bf281fd85acd0c0e6dfbd3f9934f8bef4"
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
		$sequence_0 = { 486bc038 488b0d???????? 8b440120 c1e01e c1f81f 3b442450 741a }
		$sequence_1 = { e8???????? 33db 8bf8 85c0 0f8453020000 4c8d2dea040100 }
		$sequence_2 = { 884814 0fb644243c 83f805 7511 0fb6442405 83e001 85c0 }
		$sequence_3 = { 48837c242000 7432 488b442430 4839442420 720c }
		$sequence_4 = { 488d0d13800100 33c0 8b542420 f00fb111 85c0 742c 48837c242820 }
		$sequence_5 = { 4c8d34c0 49c1fc06 4a8b84e1f0a50100 4a8b44f028 488945bf }
		$sequence_6 = { 488b09 448b0481 33d2 b95a000000 ff15???????? }
		$sequence_7 = { 4883f9fd 7706 ff15???????? 488364243000 488d0dfc7b0000 8364242800 41b803000000 }
		$sequence_8 = { 8bc2 8955e4 c1e802 8bf2 8b55f0 83e603 }
		$sequence_9 = { b803000000 50 68???????? ff763c e8???????? 83c40c 85c0 }
		$sequence_10 = { 7510 46 83c028 3bf2 }
		$sequence_11 = { 8a4dfe 84c0 8a45ff 7909 }
		$sequence_12 = { 53 ff15???????? 50 ff15???????? 834f1406 8b15???????? 8b4df4 }
		$sequence_13 = { 6bd730 8b0c8d30430110 c644112800 85f6 740c 56 e8???????? }
		$sequence_14 = { 8945fc ff15???????? 85c0 7460 c603e9 8b4704 2bc3 }
		$sequence_15 = { 83feff 0f8432010000 57 6a01 83caff 8d4de8 }

	condition:
		7 of them and filesize <253952
}