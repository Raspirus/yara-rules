rule MALPEDIA_Win_Graphical_Neutrino_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b16102ee-c7a4-5abc-870b-b75814e7493c"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphical_neutrino"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.graphical_neutrino_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "650397c4d3167e6ec1c66b8947fe66982f57b8190e3a878616091180b7325b66"
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
		$sequence_0 = { 4489c7 4889f2 48c7410800000000 4531c0 4889d9 4c8d6c2450 e8???????? }
		$sequence_1 = { ff15???????? 4883fe10 7f1c 41b828400000 }
		$sequence_2 = { 48c78424c800000002000000 48898424c0000000 e8???????? 4c8da424c0000000 488d842460050000 48c78424c800000002000000 }
		$sequence_3 = { eb07 b001 80fa09 7478 }
		$sequence_4 = { 8806 488d4602 885601 eb2d b964000000 }
		$sequence_5 = { 53 4883ec20 4c8b6108 4889cb 4c3b6110 740f }
		$sequence_6 = { ebcc 31db 4c89ea 4c89e1 4189de ffc3 }
		$sequence_7 = { 7430 c605????????01 31c0 8a1403 881406 48ffc0 4883f81f }
		$sequence_8 = { 4155 4154 53 4883ec20 c60100 4889cb 4989d5 }
		$sequence_9 = { bd07000000 eb32 41b9a0860100 bd06000000 eb25 41b910270000 bd05000000 }

	condition:
		7 of them and filesize <674816
}