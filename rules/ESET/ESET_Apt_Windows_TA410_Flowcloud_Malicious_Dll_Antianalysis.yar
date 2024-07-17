rule ESET_Apt_Windows_TA410_Flowcloud_Malicious_Dll_Antianalysis : FILE
{
	meta:
		description = "Matches anti-analysis techniques used in TA410 FlowCloud hijacking DLL."
		author = "ESET Research"
		id = "b38a1d4d-5053-5a6d-be8c-c00261936417"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L519-L552"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "8f14352118d32a43c17f70bd753acc48bd314965f10ab97818e8a434bbda96d9"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            33 C0
            E8 ?? ?? ?? ??
            83 C0 10
            3D 00 00 00 80
            7D 01
            EB FF
            E0 50
            C3
        }

	condition:
		uint16(0)==0x5a4d and all of them
}