rule VOLEXITY_Apt_Py_Bluelight_Ldr : INKYSQUID
{
	meta:
		description = "Python Loader used to execute the BLUELIGHT malware family."
		author = "threatintel@volexity.com"
		id = "f8da3e40-c3b0-5b7f-8ece-81874993d8cd"
		date = "2021-06-22"
		modified = "2021-09-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L27-L45"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "e7e18a6d648b1383706439ba923335ac4396f6b5d2a3dc8f30f63ded7df29eda"
		score = 75
		quality = 80
		tags = "INKYSQUID"
		hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "\"\".join(chr(ord(" ascii
		$s2 = "import ctypes " ascii
		$s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
		$s4 = "ctypes.memmove" ascii
		$s5 = "python ended" ascii

	condition:
		all of them
}