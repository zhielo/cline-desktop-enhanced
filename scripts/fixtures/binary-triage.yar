/* Reviewed neutral triage patterns, not malware verdicts. No includes or external modules. */
rule cline_owned_fixture {
    meta: description = "Project-owned acceptance marker; not a malware signature"
    strings: $marker = "CLINE_OWNED_TRIAGE_FIXTURE_V1"
    condition: $marker
}
rule cline_pe_header {
    meta: description = "DOS MZ prefix candidate, not PE validity or a maliciousness verdict"
    condition: uint16(0) == 0x5a4d
}
rule cline_elf_header {
    meta: description = "ELF header candidate, not validity or a maliciousness verdict"
    condition: uint32(0) == 0x464c457f
}
