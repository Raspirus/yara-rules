
rule MALPEDIA_Win_Agendacrypt_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "20fa12ae-39fc-589c-ac17-0baa3bbfd44a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agendacrypt"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.agendacrypt_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "b4f726649ba175df63b497d8d60f55fe36fe0cd2719e493aac65ae353f8a7651"
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
		$sequence_0 = { eb20 8b55ec 8975e8 89f1 57 53 e8???????? }
		$sequence_1 = { 8d55b0 e8???????? eb25 c745b000000000 8d4dd0 8d55b0 e8???????? }
		$sequence_2 = { c1e204 88443110 89f8 f7d0 c1e004 f30f7e0403 f30f7e4c0308 }
		$sequence_3 = { c1c71a 31fa 8b7b04 89c3 339d70ffffff 0fcf 21cb }
		$sequence_4 = { e9???????? 8d543210 8b7508 f20f104a30 f20f114e40 f20f104a28 f20f114e38 }
		$sequence_5 = { f20f1101 8b55f0 8d4da8 ff7518 ff7514 ff7510 ff750c }
		$sequence_6 = { f20f1145c8 0f82de010000 80ff0a 894804 0f85c9000000 8b7d0c 8b55ec }
		$sequence_7 = { f20f114c2438 f20f108c2488000000 f20f11542430 f20f105028 f20f11442440 f20f115c2418 f20f1018 }
		$sequence_8 = { e8???????? e9???????? ffb424fc000000 e8???????? e9???????? e8???????? 89c3 }
		$sequence_9 = { ffd1 83c404 8b8c24a0190000 83790400 741f 8b84249c190000 83790809 }

	condition:
		7 of them and filesize <3340288
}