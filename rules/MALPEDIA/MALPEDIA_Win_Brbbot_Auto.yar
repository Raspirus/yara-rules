rule MALPEDIA_Win_Brbbot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e240fcbc-2659-5f11-92b2-f24493c78ffd"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.brbbot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.brbbot_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "d23aa206f76a72b99ca843cfc9c1f11b947cf7f249b06e1b49eb77df3aca0670"
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
		$sequence_0 = { 7509 488d0daad10000 eb02 33c9 e8???????? 4883c438 }
		$sequence_1 = { f2ae 48f7d1 48ffc9 4c8bc1 498d8e10040000 488bd5 e8???????? }
		$sequence_2 = { 48f7d1 4c8d41ff 488d8b04010000 e8???????? }
		$sequence_3 = { 885c2470 448bee 448bfe e8???????? 488b05???????? 4889442458 }
		$sequence_4 = { 48895808 488970e8 33ff 488978b8 4c8960e0 }
		$sequence_5 = { 48f7d1 48ffc9 4881f904010000 0f8724010000 4883c9ff }
		$sequence_6 = { 81fa01010000 7d13 4863ca 8a44191c 42888401c0230100 }
		$sequence_7 = { 488bfa ff15???????? 4c8d4704 488bc8 ba08000000 ff15???????? }
		$sequence_8 = { 4c8b7540 8bd8 85c0 0f88d6020000 4c8d4da8 }
		$sequence_9 = { 33d2 488bce e8???????? ff15???????? 4c8bc6 488bc8 33d2 }

	condition:
		7 of them and filesize <198656
}