rule MALPEDIA_Win_Nim_Blackout_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5ee8f0fb-bcc5-57f1-899f-f87f9c8f8cd3"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nim_blackout"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.nim_blackout_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "38658558791a84132e6c1e0a028a41bbfaac44e317840b869e572ec902a09080"
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
		$sequence_0 = { 4889c8 83e001 84c0 7405 e8???????? 488b45f0 4885c0 }
		$sequence_1 = { 48c7401800000000 e9???????? 90 48c745e0c6000000 488d057d5c0200 488945e8 }
		$sequence_2 = { 488d057ad80000 488905???????? 488d05d85b0200 488905???????? c605????????01 48c705????????60000000 }
		$sequence_3 = { e8???????? 48c745e0e7000000 488d05c37e0200 488945e8 488b4510 488b00 ba08000000 }
		$sequence_4 = { e9???????? 90 48c785a800000000000000 48c785a000000000000000 48c7450088010000 488d05885b0100 48894508 }
		$sequence_5 = { 488945c8 488b4de8 488b55e0 4889d0 4801c0 4801d0 48c1e003 }
		$sequence_6 = { 488b1402 4889c8 4801c0 4801c8 48c1e004 4889c1 }
		$sequence_7 = { 488d0542460200 488945c8 488b4510 488b55f8 4889d1 48c1e105 488b55f0 }
		$sequence_8 = { 488b4588 488945f0 eb49 90 48c745d033000000 488d05f48e0100 488945d8 }
		$sequence_9 = { 48894508 48c785f800000000000000 48c7450084010000 488d05bf5c0100 48894508 4883bdf000000000 0f84ff000000 }

	condition:
		7 of them and filesize <1068032
}