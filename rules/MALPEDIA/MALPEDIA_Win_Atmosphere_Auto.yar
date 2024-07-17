rule MALPEDIA_Win_Atmosphere_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7ba90f14-d41a-58f9-948d-cf574aec7198"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atmosphere"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.atmosphere_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "0264599b5475822be219779f2f93298a08919e3b2fbd551146e8b50c69fa19e9"
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
		$sequence_0 = { 83ec14 56 8b7104 85f6 }
		$sequence_1 = { 88460e 33c0 894612 894616 89461a 884e1e }
		$sequence_2 = { e8???????? 8b4604 85c0 7504 33f6 eb08 }
		$sequence_3 = { 8bcf ff5338 5f 5e }
		$sequence_4 = { c645fc02 8bcc 8965e8 50 51 e8???????? }
		$sequence_5 = { 8bce 8975e8 8806 ff15???????? }
		$sequence_6 = { 8bc4 89642410 50 e8???????? }
		$sequence_7 = { 8b7c240c 8bf1 57 ff15???????? 8b470c }
		$sequence_8 = { 51 83ec10 8bc4 89642410 50 e8???????? }
		$sequence_9 = { 8bcc 8965e8 50 51 }

	condition:
		7 of them and filesize <360448
}