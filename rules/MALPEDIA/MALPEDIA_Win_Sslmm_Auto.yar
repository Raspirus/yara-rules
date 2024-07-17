
rule MALPEDIA_Win_Sslmm_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "66fe7984-4fbf-52ff-a40d-1ce2823f2352"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sslmm"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sslmm_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "d75465397d6b8b1866eed0e7ec1b8ff2d24536787a6f5113faf56887d0bb752f"
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
		$sequence_0 = { 89542440 8d4c2418 89442414 89542444 }
		$sequence_1 = { 8b8c2484000000 8bbc2480000000 8b54247c 51 57 52 8bcb }
		$sequence_2 = { 8b442438 89742418 89542468 89442460 8b44241c 33f6 8d542428 }
		$sequence_3 = { e9???????? ff15???????? 50 eb13 5f 5e }
		$sequence_4 = { 8b868c000000 68???????? 85c0 7413 6800000200 6a00 }
		$sequence_5 = { 83c40c 899374010000 33ed 8b8374010000 }
		$sequence_6 = { 83f8ff 0f8477020000 3bc5 0f84fb010000 8b9374010000 55 03d0 }
		$sequence_7 = { 83c414 3bc3 770a 6a0a }
		$sequence_8 = { 8db120010000 8b780c 42 897814 8b7808 897810 }
		$sequence_9 = { 8b7c2424 e9???????? 50 8bcf eb2e }

	condition:
		7 of them and filesize <188416
}