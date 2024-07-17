
rule MALPEDIA_Win_Scieron_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f9adad1f-0463-5c84-9844-b56939af8a07"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scieron"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.scieron_auto.yar#L1-L114"
		license_url = "N/A"
		logic_hash = "0253954720ef9ca79516bb585b52e8d461b9169ed80f649da26edf6b8044019f"
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
		$sequence_0 = { 8bc6 ff75f8 e8???????? 59 59 }
		$sequence_1 = { 57 ff7508 8d859cf9ffff 68???????? }
		$sequence_2 = { 68???????? ff15???????? 50 ffd3 ffd0 807d0c02 742a }
		$sequence_3 = { 8bec 83e4f8 b81c800000 e8???????? 53 }
		$sequence_4 = { 897574 ff15???????? 8d4574 50 56 56 }
		$sequence_5 = { eb65 8b4734 50 894574 8d472c 50 }
		$sequence_6 = { 8bf8 85ff 7418 8d45fc }
		$sequence_7 = { 40 40 663938 75df }
		$sequence_8 = { 033e 68???????? 68???????? ff15???????? }
		$sequence_9 = { 83a61c02000000 33c0 40 5f 5d }

	condition:
		7 of them and filesize <100352
}