import "pe"

import "dotnet"


rule SECUINFRA_APT_Bitter_Maldoc_Verify : CVE_2018_0798
{
	meta:
		description = "Detects Bitter (T-APT-17) shellcode in oleObject (CVE-2018-0798)"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "8e0e32d3-f00e-5145-9386-f42ddca703ae"
		date = "2022-06-01"
		modified = "2022-07-05"
		reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/APT/APT_Bitter_T-APT-17.yar#L11-L40"
		license_url = "N/A"
		logic_hash = "1d30e2ad0d99d274a4e3dd029ff41ec05e8ba4160bea37762bce1bb5286493d8"
		score = 75
		quality = 70
		tags = "CVE-2018-0798"
		tlp = "WHITE"
		hash0 = "0c7158f9fc2093caf5ea1e34d8b8fffce0780ffd25191fac9c9b52c3208bc450"
		hash1 = "bd0d25194634b2c74188cfa3be6668590e564e6fe26a6fe3335f95cbc943ce1d"
		hash2 = "3992d5a725126952f61b27d43bd4e03afa5fa4a694dca7cf8bbf555448795cd6"

	strings:
		$xor_string0 = "LoadLibraryA" xor
		$xor_string1 = "urlmon.dll" xor
		$xor_string2 = "Shell32.dll" xor
		$xor_string3 = "ShellExecuteA" xor
		$xor_string4 = "MoveFileA" xor
		$xor_string5 = "CreateDirectoryA" xor
		$xor_string6 = "C:\\Windows\\explorer" xor
		$padding = {000001128341000001128341000001128342000001128342}

	condition:
		3 of ($xor_string*) and $padding
}