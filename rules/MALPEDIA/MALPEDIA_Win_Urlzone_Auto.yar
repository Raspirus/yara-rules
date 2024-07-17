rule MALPEDIA_Win_Urlzone_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "73713fa1-9237-58d2-8cc2-5acf9c265fc9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.urlzone"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.urlzone_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "4cce61429410ef9f511dc19a60899f126670164d7c8bb8ef8edba2014cda32d1"
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
		$sequence_0 = { 7c32 80f839 7f05 80e830 eb22 }
		$sequence_1 = { 80fc39 7f05 80ec30 eb22 }
		$sequence_2 = { 7f05 80ec30 eb22 80fc41 7c54 }
		$sequence_3 = { 80c00a eb10 80f861 7c11 80f866 }
		$sequence_4 = { 5f 5e c3 57 51 89c7 }
		$sequence_5 = { 80c40a eb10 80fc61 7c42 80f866 7f3d }
		$sequence_6 = { 7f0c 80e861 80c00a c0e004 08e0 }
		$sequence_7 = { 80f841 7c23 80f846 7f08 }
		$sequence_8 = { 80f839 7f05 80e830 eb22 80f841 7c23 }
		$sequence_9 = { 80ec30 eb22 80fc41 7c54 }

	condition:
		7 of them and filesize <704512
}