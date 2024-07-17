rule MALPEDIA_Win_Attor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "de68d27a-a7e8-5baa-94a2-9db640461043"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.attor"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.attor_auto.yar#L1-L165"
		license_url = "N/A"
		logic_hash = "9ffbefbd2b4397dd03e1eba42ffa85ea59dac9e4723a113680ffe4af7c4fe1e3"
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
		$sequence_0 = { 83f801 7411 3d81000000 740a }
		$sequence_1 = { 33c0 488b6c2450 4883c420 415c 5f 5e }
		$sequence_2 = { 488b8c24b0000000 4c8b642468 4885c9 7402 8919 408ac5 }
		$sequence_3 = { 488b8c2490000000 4885c9 0f8441020000 41b802000000 8bd5 ff15???????? 85c0 }
		$sequence_4 = { 48395c2430 0f8447010000 b101 e8???????? }
		$sequence_5 = { 48c744243000000000 7414 33c9 e8???????? 488b8c2490000000 }
		$sequence_6 = { 7435 488b442440 488b8c2490000000 4533c0 418d5002 4d8bcf }
		$sequence_7 = { 4533c0 4d8bcc 418d5002 44896c2420 ff15???????? }
		$sequence_8 = { 8b4c2418 50 55 8b2d???????? 6a00 }
		$sequence_9 = { 740a 83f808 7405 83f811 }
		$sequence_10 = { 56 ff15???????? 8d4c2418 8d54241c 51 52 }
		$sequence_11 = { 83c408 eb06 8b35???????? 897c241c 8b7c2420 85ff }
		$sequence_12 = { 83c40c 89442420 85c0 0f842b010000 8b4c2430 8d7108 }
		$sequence_13 = { 85c0 0f840c010000 8b54241c 57 52 }
		$sequence_14 = { 897504 c644241301 740a 8b4c2418 }
		$sequence_15 = { 8b44243c 3bc7 7434 8b54241c }

	condition:
		7 of them and filesize <2023424
}