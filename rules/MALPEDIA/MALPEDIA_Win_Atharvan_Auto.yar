
rule MALPEDIA_Win_Atharvan_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "90143155-ec04-5a1a-8f1d-cad8e690d20c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atharvan"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.atharvan_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "4ab12aee6394d0021e81333c85382f01af297ccebc032a8d7f39b0ec61d7b92e"
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
		$sequence_0 = { 4c8d05ee7a0000 488b9540070000 488bce e8???????? 85c0 750b eb9e }
		$sequence_1 = { 423a9401d4ab0100 7566 488b03 48ffc1 8a10 48ffc0 488903 }
		$sequence_2 = { 498784f6105c0200 4885c0 7409 488bcb ff15???????? 4885db }
		$sequence_3 = { 8d0480 03c0 442be8 0f84cffbffff 418d45ff 8b848228aa0100 }
		$sequence_4 = { 750d 4c8bc6 e8???????? e9???????? 4c8bce 4c8d05e1dd0100 }
		$sequence_5 = { 498bcf ff15???????? 498bcf ff15???????? 488b4c2440 4833cc e8???????? }
		$sequence_6 = { b903000000 4c8d0564a10000 488d1565a10000 e8???????? }
		$sequence_7 = { 498bcf ff15???????? 488bd8 eb02 33db 4c8d3d028cffff 4885db }
		$sequence_8 = { 7528 48833d????????00 741e 488d0d943e0100 e8???????? 85c0 }
		$sequence_9 = { 83f801 751f 488b0d???????? 488d1d356c0100 483bcb 740c }

	condition:
		7 of them and filesize <348160
}