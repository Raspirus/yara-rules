
rule SIGNATURE_BASE_XMRIG_Monero_Miner_Config : FILE
{
	meta:
		description = "Auto-generated rule - from files config.json, config.json"
		author = "Florian Roth (Nextron Systems)"
		id = "374efe7f-9ef2-5974-8e24-f749183ab2d0"
		date = "2018-01-04"
		modified = "2023-12-05"
		reference = "https://github.com/xmrig/xmrig/releases"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/pua_xmrig_monero_miner.yar#L35-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5df14af366cdb0a5bf6fd88b50876fd78abfe0b795cf10af8fab0d23a54f700f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
		hash2 = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"

	strings:
		$s2 = "\"cpu-affinity\": null,   // set process affinity to CPU core(s), mask \"0x3\" for cores 0 and 1" fullword ascii
		$s5 = "\"nicehash\": false                  // enable nicehash/xmrig-proxy support" fullword ascii
		$s8 = "\"algo\": \"cryptonight\",  // cryptonight (default) or cryptonight-lite" fullword ascii

	condition:
		( uint16(0)==0x0a7b or uint16(0)==0x0d7b) and filesize <5KB and 1 of them
}