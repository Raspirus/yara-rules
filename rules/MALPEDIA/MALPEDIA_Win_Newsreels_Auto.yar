rule MALPEDIA_Win_Newsreels_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d0a51f50-02b3-5e2e-87a4-1bcf6809c906"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newsreels"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.newsreels_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "fc1a2dbb3b05d6d5724530e791c74623a98e89ee20e6cc268616876a0ad255a8"
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
		$sequence_0 = { 7516 39ac247c030000 7d37 5e 5d 83c8ff }
		$sequence_1 = { 53 53 8d8424e0030000 68???????? 50 66899c24a0000000 c784249c00000001010000 }
		$sequence_2 = { ff15???????? e9???????? 6a4d 6a08 68???????? e8???????? 8b35???????? }
		$sequence_3 = { 6a4d f2ae f7d1 49 }
		$sequence_4 = { 8d542460 8d4c2454 83c448 8b02 8b11 3bc2 }
		$sequence_5 = { 83c408 85db 750a 5e 5d }
		$sequence_6 = { 33f6 e8???????? 8bd8 83c408 85db 7516 }
		$sequence_7 = { 51 e8???????? 8b742430 8b542431 8b442432 81e6ff000000 8b4c2433 }
		$sequence_8 = { 8b9c24e0110000 8808 8b15???????? 8bcb 8bc1 }
		$sequence_9 = { 51 6a09 6a08 52 66894808 e8???????? }

	condition:
		7 of them and filesize <65536
}