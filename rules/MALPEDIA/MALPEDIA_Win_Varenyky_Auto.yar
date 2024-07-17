
rule MALPEDIA_Win_Varenyky_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "799963a3-0366-58c7-b923-0a51c9db342a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.varenyky"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.varenyky_auto.yar#L1-L122"
		license_url = "N/A"
		logic_hash = "9e07244b9e5d336f26b69f46ff4024108fa6443c2648edcc9fb5aa11d967154b"
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
		$sequence_0 = { 8b3d???????? 8b542418 6a00 52 8d8424c0130000 50 55 }
		$sequence_1 = { 8d542435 6a00 52 c644243c00 e8???????? }
		$sequence_2 = { 6880000000 8bd6 52 ff15???????? 6803010000 8d842485020000 }
		$sequence_3 = { 83c40c 6a40 898424a4010000 898c249c010000 8a0d???????? 899424a0010000 8d442450 }
		$sequence_4 = { 03f0 0fbe01 3bc3 75f0 }
		$sequence_5 = { 57 e8???????? 83c404 3c32 }
		$sequence_6 = { 8d84244d030000 53 50 c744242404010000 889c2454030000 e8???????? }
		$sequence_7 = { 51 ffd6 68???????? 8d542474 52 ffd7 }
		$sequence_8 = { 56 57 6803010000 8d44243d 53 50 885c2444 }
		$sequence_9 = { 41 03e8 0fbe01 3bc3 75f0 0fbe842440020000 }

	condition:
		7 of them and filesize <24846336
}