
rule MALPEDIA_Win_Avcrypt_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f0c2c6c6-0e09-5b4b-89b9-13d38222f492"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avcrypt"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.avcrypt_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "ac05395b3ceaf430ebcb56d0def5da87a92c07f9636a33b891b2fc3647618543"
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
		$sequence_0 = { 68???????? ffd3 834dfcff 8d4dd8 56 6a01 e8???????? }
		$sequence_1 = { 8bc7 8bcf c1f805 83e11f c1e106 030c8580b54300 eb05 }
		$sequence_2 = { 8d4dc0 56 e8???????? 59 6a0e 33f6 5b }
		$sequence_3 = { c705????????70484300 c705????????8cbf4300 890d???????? 8935???????? }
		$sequence_4 = { 50 ff15???????? 83c8ff e9???????? 57 6a09 59 }
		$sequence_5 = { ff15???????? 85c0 7507 68???????? ffd6 895de4 837dd000 }
		$sequence_6 = { 68???????? e8???????? 83ec18 c745fc15000000 8bcc 8965d4 53 }
		$sequence_7 = { c645fc0e 837db800 7519 68???????? 8d8d78ffffff e8???????? }
		$sequence_8 = { e8???????? 68???????? 8d8d84feffff c645fc08 e8???????? 68???????? 8d8d9cfeffff }
		$sequence_9 = { e8???????? c645fc01 8b5de0 85db 7404 8b13 }

	condition:
		7 of them and filesize <6160384
}