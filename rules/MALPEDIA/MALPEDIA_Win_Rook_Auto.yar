rule MALPEDIA_Win_Rook_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "18a58274-365f-5d90-8056-28a56db76f76"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rook"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.rook_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "8b05af9f0d6f5102cdf2e062676438cba9dcdb9d6b25adc560d5025ee81a7b52"
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
		$sequence_0 = { 488d05478d0200 c7470801000000 48c7471003000000 48894748 488d05c59e0200 }
		$sequence_1 = { 0f8521ffffff 44882b eb7b 488b9540070000 4c8d05979e0000 498bce }
		$sequence_2 = { 85c0 0f85f5020000 488b8d08080000 488d85f8070000 4c89a424c0080000 488d15ffb90400 }
		$sequence_3 = { ff15???????? 488bd3 488d0d82ac0400 448bc0 e8???????? 488b0d???????? 4c8bc3 }
		$sequence_4 = { 4433d0 418bc1 48c1e808 0fb6c8 41c1e208 420fb6843170990500 4433d0 }
		$sequence_5 = { 488d85f8070000 4c89a424c0080000 488d15ffb90400 4889442428 4c8d25d3450500 4c89ac24b8080000 }
		$sequence_6 = { 488d542460 488d0d1c380500 e8???????? 488d9510020000 498bcc ff15???????? 4839bd10020000 }
		$sequence_7 = { 48894760 488d0535980200 c7475001000000 48c7475804000000 48894778 488d050b710300 c7476801000000 }
		$sequence_8 = { 4898 4d8d3446 83ed01 7586 4885f6 0f84d3000000 488bce }
		$sequence_9 = { 4c8d05f7140300 488986b0000000 488d8e98000000 e8???????? 8bd8 85c0 0f8517ffffff }

	condition:
		7 of them and filesize <843776
}