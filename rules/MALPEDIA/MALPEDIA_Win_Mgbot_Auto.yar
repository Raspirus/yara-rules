
rule MALPEDIA_Win_Mgbot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dd03dc94-bb3a-5cad-8f13-4bbe4b7f90a6"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mgbot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mgbot_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "7310ce51cc81391fc78e9881bf8f490b2a783d4789728f7661df3e6bdca512d7"
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
		$sequence_0 = { 6808020000 e8???????? 6804010000 8bf0 6a00 }
		$sequence_1 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 e8???????? }
		$sequence_2 = { 5b 8be5 5d c20800 6808020000 }
		$sequence_3 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 }
		$sequence_4 = { 8be5 5d c20800 6808020000 e8???????? }
		$sequence_5 = { 6808020000 e8???????? 6804010000 8bf0 }
		$sequence_6 = { 5d c20800 6808020000 e8???????? }
		$sequence_7 = { 8be5 5d c20800 6808020000 }
		$sequence_8 = { 5b 8be5 5d c20800 6808020000 e8???????? }
		$sequence_9 = { 0f8553ffffff 5f 33c0 5e }

	condition:
		7 of them and filesize <1677312
}