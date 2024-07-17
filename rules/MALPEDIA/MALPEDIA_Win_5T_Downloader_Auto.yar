
rule MALPEDIA_Win_5T_Downloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "fe4393a3-e3cd-5e60-a348-fa50df874e7a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.5t_downloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.5t_downloader_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "708a5991b6f83db848239b1110cc9bc587325f0c0450305b55a83b6de5bbd18e"
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
		$sequence_0 = { 7409 83781800 7403 5d }
		$sequence_1 = { 85c9 7409 83781800 7403 5d }
		$sequence_2 = { 85c9 7409 83781800 7403 }
		$sequence_3 = { 85c0 7416 83781400 7510 }
		$sequence_4 = { 85c9 7409 83781800 7403 5d ffe1 83c8ff }
		$sequence_5 = { 8b4508 85c0 7416 83781400 7510 }
		$sequence_6 = { 55 8bec 8b4508 85c0 7416 83781400 7510 }
		$sequence_7 = { 85c9 7409 83781800 7403 5d ffe1 }
		$sequence_8 = { 7409 83781800 7403 5d ffe1 83c8ff }
		$sequence_9 = { 8bec 8b4508 85c0 7416 83781400 7510 }

	condition:
		7 of them and filesize <539648
}