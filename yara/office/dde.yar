rule OfficeDDE1 {
    strings:
        $s1 = "w:instrText"

    condition:
      filename matches /word\/document.xml/ and $s1
}

rule OfficeDDE2 {
    strings:
        $s1 = "w:fldSimple"
        $s2 = "w:instr"

    condition:
      filename matches /word\/document.xml/ and $s1 and $s2
}
