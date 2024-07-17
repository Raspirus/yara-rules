
rule MALPEDIA_Win_Cryptoluck_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a59fe2e6-4321-5ca6-b53f-4f7ee8914f9a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptoluck"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.cryptoluck_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "6db6bc0e7d4030ac1b4c7c7367ac728b4b155db8cbff6f59645d89ef531abf3a"
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
		$sequence_0 = { 7409 c745d880720010 eb07 c745d878720010 837d1000 7409 c745d475720010 }
		$sequence_1 = { 44 15f40010ff 35ec001eff 20d7 59 392d???????? 1288ff35d403 }
		$sequence_2 = { 8b85e4fbffff 50 e8???????? 83c408 8985c4fbffff 83bdc4fbffff00 }
		$sequence_3 = { 8b4df8 51 ff15???????? 85c0 7431 8b550c }
		$sequence_4 = { 85c0 0f84e8000000 c745ec00000000 8d45ec 50 8d4df0 51 }
		$sequence_5 = { ff15???????? 85c0 7419 8b4d14 }
		$sequence_6 = { 99 2bc2 8bc8 d1f9 8b45ac 99 2bc2 }
		$sequence_7 = { ff15???????? 8b0d???????? 51 8b95c8fdffff 52 68ff0f0000 }
		$sequence_8 = { c60000 8b4de0 83c101 894de0 8b55dc }
		$sequence_9 = { ff15???????? 8985e8faffff 83bde8faffffff 0f84d9000000 b8424d0000 668985d4faffff 8b8df4faffff }

	condition:
		7 of them and filesize <229376
}