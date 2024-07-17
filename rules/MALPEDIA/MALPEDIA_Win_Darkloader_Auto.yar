rule MALPEDIA_Win_Darkloader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "601e152a-7554-5605-b5d8-66c528809ef1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkloader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.darkloader_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "3bce0c9d521648c67df3e1e758ce6a8ac769bd1d815dcd4dfd750767fac4bfe8"
		score = 75
		quality = 73
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
		$sequence_0 = { e8???????? 8bb42434020000 c1e607 68???????? 89b42438020000 8dbe10a10010 }
		$sequence_1 = { c70424???????? e8???????? c70424???????? 8bf8 56 e8???????? }
		$sequence_2 = { 51 ff36 8b00 8b00 8986b0010000 ff96bc010000 }
		$sequence_3 = { 57 ff74241c e8???????? 03c3 0fb73470 }
		$sequence_4 = { 3c5f 7447 3c2e 7443 3c7e }
		$sequence_5 = { 8b7c240c 8bcf 8906 8d5101 8a01 41 84c0 }
		$sequence_6 = { 84c0 740b 80f90d 7519 }
		$sequence_7 = { 894c241c 85c9 0f84b3000000 8b4020 }
		$sequence_8 = { 6bc503 40 50 e8???????? be???????? 8d7c2418 }
		$sequence_9 = { 83c428 50 6a40 6a05 53 ffd6 }

	condition:
		7 of them and filesize <124928
}