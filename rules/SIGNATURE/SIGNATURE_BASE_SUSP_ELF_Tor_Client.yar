
rule SIGNATURE_BASE_SUSP_ELF_Tor_Client : FILE
{
	meta:
		description = "Detects VPNFilter malware"
		author = "Florian Roth (Nextron Systems)"
		id = "1be6528d-1b60-50da-8125-2ef73b8aeb4f"
		date = "2018-05-24"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_vpnfilter.yar#L80-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2b67b32c5b8441c9b38e3bfeefa7f59c2767e29985adcba7d52e858847d37e47"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "afd281639e26a717aead65b1886f98d6d6c258736016023b4e59de30b7348719"

	strings:
		$x1 = "We needed to load a secret key from %s, but it was encrypted. Try 'tor --keygen' instead, so you can enter the passphrase." fullword ascii
		$x2 = "Received a VERSION cell with odd payload length %d; closing connection." fullword ascii
		$x3 = "Please upgrade! This version of Tor (%s) is %s, according to the directory authorities. Recommended versions are: %s" fullword ascii

	condition:
		uint16(0)==0x457f and 1 of them
}