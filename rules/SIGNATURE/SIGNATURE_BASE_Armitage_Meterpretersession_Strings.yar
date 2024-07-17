
rule SIGNATURE_BASE_Armitage_Meterpretersession_Strings : FILE
{
	meta:
		description = "Detects Armitage component"
		author = "Florian Roth (Nextron Systems)"
		id = "c49fdb73-1c95-5c63-b039-2fddb77290dc"
		date = "2017-12-24"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_armitage.yar#L33-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3a21a42df8f15e3e81c797feb284edfe2de7d1c182547e8606f0e48dc08f6939"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
		hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"

	strings:
		$s1 = "session.meterpreter_read" fullword ascii
		$s2 = "sniffer_dump" fullword ascii
		$s3 = "keyscan_dump" fullword ascii
		$s4 = "MeterpreterSession.java" fullword ascii

	condition:
		filesize <30KB and 1 of them
}