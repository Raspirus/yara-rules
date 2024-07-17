
rule MALPEDIA_Win_Postnaptea_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "66a4e77d-c854-5ed3-94ad-0ea65d80b627"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.postnaptea"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.postnaptea_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "8a33afe097a88ce8212670a3e80b58d6a5513693490a76a85e445ee8529ba924"
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
		$sequence_0 = { c744247418f561f5 c744247867f50000 4863c2 488d4c2450 488d0c41 0fb7c2 662bc3 }
		$sequence_1 = { ffc2 83fa1a 72e3 6644896c2474 488d442440 488bd3 0f1f440000 }
		$sequence_2 = { ffd7 85c0 0f842c010000 4c8d052d4b0600 ba04010000 498bce e8???????? }
		$sequence_3 = { e9???????? 418b8520280000 4d8bce 48634c2440 4c8bc6 2bc1 48034c2460 }
		$sequence_4 = { c745c000f50cf5 c745c407f528f5 c745c80cf508f5 c745cc02f53cf5 c745d006f50bf5 c745d419f50bf5 c745d81bf54ef5 }
		$sequence_5 = { ff15???????? 4533e4 4d85f6 0f8418100000 498bce e9???????? 448b85b0000000 }
		$sequence_6 = { c7851001000031f56df5 c785140100006df54ef5 c7851801000005f50ef5 c7851c0100000ff50000 418bd4 0f1f440000 4863c2 }
		$sequence_7 = { c78520020000a081b081 c78524020000a281ba81 c78528020000fa81b181 c7852c020000ba81bb81 33c0 66898530020000 418bd5 }
		$sequence_8 = { 488b05???????? 4885c0 7515 488d55b0 b9bd59e821 e8???????? 488905???????? }
		$sequence_9 = { ffd7 c7856007000079f57af5 c785640700007bf515f5 c785680700000df528f5 c7856c0700006bf540f5 c7857007000020f506f5 c7857407000007f516f5 }

	condition:
		7 of them and filesize <2457600
}