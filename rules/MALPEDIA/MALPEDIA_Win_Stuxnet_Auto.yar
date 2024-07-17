
rule MALPEDIA_Win_Stuxnet_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e84f453f-688f-5279-9168-a0cb915408b7"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.stuxnet_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "9f5d56947917572e8a9b84c0e49b11ae5a34a590900f3243fcc05249be23cf0d"
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
		$sequence_0 = { e8???????? 8b5dec 8b45f0 895df4 8945f8 ff770c 8d75ec }
		$sequence_1 = { c20400 b8???????? e8???????? 51 6a08 e8???????? 59 }
		$sequence_2 = { e8???????? 33db 895dfc 53 8d45d8 50 6802000080 }
		$sequence_3 = { 6aff 68???????? 64a100000000 50 64892500000000 83ec64 8d442420 }
		$sequence_4 = { eb02 33f6 c645fc00 8b4f1c 3bf1 740a 85c9 }
		$sequence_5 = { 837df008 8b45dc 7303 8d45dc 50 8d431c e8???????? }
		$sequence_6 = { c706???????? e8???????? c645fc01 c6462400 834dfcff 8b4df4 8bc6 }
		$sequence_7 = { a5 50 a5 ff5130 85c0 7cb0 8b9b48080000 }
		$sequence_8 = { ff750c ff7510 8d45e4 50 e8???????? c645fc01 8d4def }
		$sequence_9 = { ff7508 8d4df4 e8???????? 837d14ff 7d04 33c0 eb12 }

	condition:
		7 of them and filesize <2495488
}