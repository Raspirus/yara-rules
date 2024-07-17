
rule MALPEDIA_Win_Chir_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "18ccfa9f-30e1-5e52-b265-5cee479b1cb5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chir"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.chir_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "3243cfbae6092a474cd7d4359f5703dd14295b3f14d9c12875310667b98d1cdf"
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
		$sequence_0 = { 47 8811 3bf8 72e7 }
		$sequence_1 = { 8d4c3df0 8a11 80f2fc 80c202 }
		$sequence_2 = { e8???????? 48 59 8bcb 7419 }
		$sequence_3 = { 5e 7419 8d4c35f8 8a11 80f2fc }
		$sequence_4 = { 8d45f0 50 c745f021352432 c745f451173300 e8???????? 48 }
		$sequence_5 = { c745f451173300 e8???????? 48 59 8bfb }
		$sequence_6 = { 8d4c35f0 8a11 80f2fc 80c202 80f201 }
		$sequence_7 = { 8a19 80f3fc 80c302 80f301 80c303 42 }
		$sequence_8 = { 7415 8d4c15f8 8a01 34fc }
		$sequence_9 = { 8a11 80f2fc 80c202 80f201 80c203 46 8811 }

	condition:
		7 of them and filesize <286720
}