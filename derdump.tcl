#!/usr/bin/tclsh
package require pki

set ::pki::oids(2.5.4.42)  "givenName"
set ::pki::oids(1.2.643.100.1)  "OGRN"
set ::pki::oids(1.2.643.100.5)  "OGRNIP"
set ::pki::oids(1.2.643.3.131.1.1) "INN"
set ::pki::oids(1.2.643.100.3) "SNILS"
#Для КПП ЕГАИС
set ::pki::oids(1.2.840.113549.1.9.2) "UN"
#set ::pki::oids(1.2.840.113549.1.9.2) "unstructuredName"
#Алгоритмы подписи
#    set ::pki::oids(1.2.643.2.2.19) "ГОСТ Р 34.10-2001"
set ::pki::oids(1.2.643.2.2.3) "GOST R 34.10-2001 with GOST R 34.11-94"
set ::pki::oids(1.2.643.2.2.19) "GOST R 34.10-2001"
set ::pki::oids(1.2.643.7.1.1.1.1) "GOST R 34.10-2012-256"
set ::pki::oids(1.2.643.7.1.1.1.2) "GOST R 34.10-2012-512"
set ::pki::oids(1.2.643.7.1.1.3.2) "GOST R 34.10-2012-256 with GOSTR 34.11-2012-256"
set ::pki::oids(1.2.643.7.1.1.3.3) "GOST R 34.10-2012-512 with GOSTR 34.11-2012-512"
set ::pki::oids(1.2.643.100.113.1) "KC1 Class Sign Tool"
set ::pki::oids(1.2.643.100.113.2) "KC2 Class Sign Tool"

array set ::dn_fields {
        C "Country" ST "State" L "Locality" STREET "Adress" TITLE "Title"
        O "Organization" OU "Organizational Unit"
        CN "Common Name" SN "Surname" GN "Given Name" INN "INN" OGRN "OGRN" OGRNIP "OGRNIP" SNILS "SNILS" EMAIL "Email Address"
    }

proc usage {use } {
    puts "Copyright(C) LISSI-Soft Ltd (http://soft.lissi.ru) 2019-2019"
    if {$use == 1} {
	puts "Usage:\nderdump <file with asn1-code> <file for save output | stdout>  <raw \[0|1\]> <der|pem|hex>\n"
    }
}
if {[llength $argv] != 4 } {
    usage 1
    puts "Bad usage!"
    exit
}
set inform [lindex $argv 3]
if {$inform != "der" && $inform != "pem" && $inform != "hex"} {
    usage 1
    puts "Bad usage!"
    exit
}
set file [lindex $argv 0]
if {![file exists $file]} {
    puts "File $file not exist"
    usage 1
    exit
}
puts "Loading file: $file"
set fd [open $file]
chan configure $fd -translation binary
set data [read $fd]
close $fd
if {$data == "" } {
    puts "Bad file=$file"
    usage 1
    exit
}
if {$inform == "hex"} {
    set b [string map {"\n" "" "\t" "" "\r" "" ":" "" "." "" " " ""} $data]
    set data [binary format H* $b]
} elseif {$inform == "pem"} {
#PEM в трактовке openssl
	set head [string range $data 0 10]
	set i [string equal "-----BEGIN " $head]
	if {$i != 1} {
	    puts "Bad format\nCannot \n-----BEGIN ...-----"
	    usage 1
	    exit
	}
	set ind [string first "-----" $data 12]
	if {$ind == -1} {
	    puts "Bad format\nCannot \n-----BEGIN ...-----"
	    usage 1
	    exit
	}
	append head [string range $data 11 $ind+4]
	set tail "-----END "
	append tail [string range $data 11 $ind+4]
	set data [string map {"\r" ""} $data]
	array set parsed [::pki::_parse_pem $data $head $tail]
	set data $parsed(data)
    if {$data == "" } {
	puts "Bad file=$file"
	usage 1
	exit
    }
}

set f [lindex $argv 1]
if {$f != "stdout"} {
set fdout [open $f w]
chan configure $fdout -translation binary
} else {
    set fdout $f
}

set raw [lindex $argv 2]
if {$raw != 0 && $raw != 1} {
    usage 1
    puts "Bad usage!"
    exit
}

set ::prettyTagType  {

    "End of Contents"
    "Boolean"
    "Integer"
    "Bit String"
    "Octet String"
    "NULL"
    "Object Identifier"
    "0x07"
    "0x08"
    "0x09"
    "Enumerated"
    "0x0B"
    "UTF8 String"
    "0x0D"
    "0x0E"
    "0x0F"
    "Sequence"
    "Set"
    "Numeric String"
    "Printable String"
    "T61 String"
    "0x15"
    "IA5 String"
    "UTC Time"
    "Generalized Time"
    "0x19"
    "Visible String"
    "0x1B"
    "Universal String"
    "0x1D"
    "BMP String"
    "High-Tag-Number"
};
#    "0x12" - Numeric String

set ::prettyColumn  0

variable SEC_ASN1_TAGNUM_MASK
set ::SEC_ASN1_TAGNUM_MASK 0x1f
set ::SEC_ASN1_HIGH_TAG_NUMBER 0x1f
set ::SEC_ASN1_CONSTRUCTED 0x20
set ::SEC_ASN1_CLASS_MASK 0xc0
set ::SEC_ASN1_UNIVERSAL 0x00
set ::SEC_ASN1_APPLICATION 0x40
set ::SEC_ASN1_CONTEXT_SPECIFIC 0x80
set ::SEC_ASN1_PRIVATE 0xc0

set ::SEC_ASN1_BOOLEAN 0x01
set ::SEC_ASN1_INTEGER 0x02
set ::SEC_ASN1_BIT_STRING 0x03
set ::SEC_ASN1_OCTET_STRING 0x04
set ::SEC_ASN1_NULL 0x05
set ::SEC_ASN1_OBJECT_ID 0x06
set ::SEC_ASN1_OBJECT_DESCRIPTOR 0x07
# External type and instance-of type   0x08 
set ::SEC_ASN1_REAL 0x09
set ::SEC_ASN1_ENUMERATED 0x0a
set ::SEC_ASN1_EMBEDDED_PDV 0x0b
set ::SEC_ASN1_UTF8_STRING 0x0c
set ::SEC_ASN1_T61_STRING 0x14
set ::SEC_ASN1_NUMERIC_STRING 0x12
set ::SEC_ASN1_UNIVERSAL_STRING 0x1c
set ::SEC_ASN1_BMP_STRING 0x1e
set ::SEC_ASN1_PRINTABLE_STRING 0x13
set ::SEC_ASN1_IA5_STRING 0x16
set ::SEC_ASN1_VISIBLE_STRING 0x1a
set ::SEC_ASN1_UTC_TIME 0x17
set ::SEC_ASN1_GENERALIZED_TIME 0x18

set ::RIGHT_MARGIN 24

proc prettyNewline {out} {
    if {$::prettyColumn != -1} {
        puts -nonewline $out "\n";
        set ::prettyColumn -1
    }
    return 0;
}


proc prettyIndent {out level} {
    if {$::prettyColumn == -1} {
        set ::prettyColumn $level;
	for {set i 0} {$i < $level} {incr i} {
            puts -nonewline $out "   ";
        }
    }

    return 0;
}

proc prettyPrintByte {out item level} {
    set rv  [prettyIndent $out $level];
   puts -nonewline $out [format "%02x "  $item]

    incr ::prettyColumn
    if {$::prettyColumn >= $::RIGHT_MARGIN} {
        return [prettyNewline $out];
    }

    return 0;
}

proc prettyPrintStringStart {out str len level} {
    set BUF_SIZE 100
    incr len -1

    if {$len >= $BUF_SIZE} {
        set len  [expr  $BUF_SIZE - 1]
    }
    
    set rv [prettyNewline $out];
    if {$rv < 0} {
        return $rv;
    }

    set rv [prettyIndent $out $level];
    if {$rv < 0} {
        return $rv;
    }


    set buf [string range $str 0 $len];
    if {$out != "stdout"} {
	puts -nonewline $out  [format "\"%s\"" $buf];
    } else {
	puts -nonewline $out  [format "\"%s\"" [encoding convertfrom utf-8 $buf]]
    }
    return 0;
}

proc prettyPrintString {out str len level raw} {
    set rv [prettyPrintStringStart $out $str $len $level];
    if {$rv < 0} {
        return rv;
    }

    set rv [prettyNewline $out];
    if {$rv < 0} {
        return $rv;
    }

    if {$raw} {
        set rv [prettyPrintLeaf $out str $len $level];
        if {$rv < 0} {
            return $rv;
        }
    }

    return 0;
}



proc prettyPrintLeaf1 {out data_var len lv} {
    upvar 1 $data_var data1
    set data $data1

    for {set i 0} {$i < $len} {incr i} {
	::asn::asnGetByte data tbyte
        set rv [prettyPrintByte $out $tbyte $lv];
        if {$rv < 0} {
            return $rv;
        }
    }
    return [prettyNewline $out];
}
proc prettyPrintLeaf {out data_var len lv} {
    upvar 1 $data_var data

    for {set i 0} {$i < $len} {incr i} {
	::asn::asnPeekByte data tbyte $i
        set rv [prettyPrintByte $out $tbyte $lv];
        if {$rv < 0} {
            return $rv;
        }
    }
    return [prettyNewline $out];
}

proc getInteger256  {data_var nb} {
    set data $data_var

    ::asn::asnGetBytes data $nb lengthBytes

    switch $nb {
        1 { binary scan $lengthBytes     cu length }
        2 { binary scan $lengthBytes     Su length }
        3 { binary scan \x00$lengthBytes Iu length }
        4 { binary scan $lengthBytes     Iu length }
        default {
            binary scan $lengthBytes H* hexstr
	    scan $hexstr %llx length
        }
    }
    return $length
}

proc prettyPrintLength {out data_var len_deritem lenp_var indefinitep_var lv raw} {
    upvar 1 $data_var data1 $indefinitep_var indefinitep $lenp_var lenp

    puts -nonewline $out " ";

    set indefinitep 0
    
    set data $data1
    ::asn::asnGetByte data lbyte

    set lenLen  1;
    if {$lbyte >= 0x80} {
# Multibyte length 
        set nb [expr $lbyte & 0x7f];
        if {$nb > 4} {
            return -1;
        }
        if {$nb > 0} {
            if {$nb > $len_deritem} {
                return -1;
            }
            set il [getInteger256 $data $nb];
            if {$il < 0} {
                return -1;
            }
            set lenp $il;
        } else {
            set lenp  0;
            set indefinitep 1
        }
        incr lenLen $nb;
        if {$raw} {
            set rv  [prettyPrintByte $out $lbyte $lv]
            if {$rv < 0} {
                return $rv;
            }
            
	    for {set i 0} {$i < $nb} {incr i} {
		::asn::asnGetByte data di
                set rv [prettyPrintByte $out $di $lv]
                if {$rv < 0} {
                    return $rv;
                }
            }
        }
    } else {
        set lenp  $lbyte;
        if {$raw} {
            set rv [prettyPrintByte $out $lbyte $lv]
            if {$rv < 0} {
                return rv;
            }
        }
    }
    if {$indefinitep} {
        puts -nonewline $out "(indefinite)\n";
    } else {
        puts -nonewline $out  [format "(%d)\n" $lenp];
    }

    set ::prettyColumn  -1;
    return $lenLen;
}


proc prettyPrintTag {out src_var end codep_var level raw} {
    upvar 1 $src_var src $codep_var codep
    if {[catch { ::asn::asnPeekByte src code } res] } {
	    return -1
    }

    if {![info exists code]} {
	return -1
    }
    
    set tagnum [expr $code & $::SEC_ASN1_TAGNUM_MASK ]

#     * NOTE: This code does not (yet) handle the high-tag-number form!

    if {$tagnum == $::SEC_ASN1_HIGH_TAG_NUMBER} {
        return -1;
    }

    if {$raw} {
        set rv [prettyPrintByte $out $code $level];
    } else {
        set rv  [prettyIndent $out $level];
    }

    if {$rv < 0} {
        return $rv;
    }

    if { [expr $code & $::SEC_ASN1_CONSTRUCTED]} {
	puts -nonewline $out "C-"
    }
    set class [format "0x%02x" [expr $code & $::SEC_ASN1_CLASS_MASK ]]

    switch -- $class \
        $::SEC_ASN1_UNIVERSAL  { \
    	    puts -nonewline $out [format "%s " [lindex $::prettyTagType $tagnum]] \
    	} \
        $::SEC_ASN1_APPLICATION { \
            puts -nonewline $out [format "Application: %d " $tagnum] \
        } \
        $::SEC_ASN1_CONTEXT_SPECIFIC { \
            puts -nonewline $out [format "\[%d\] " $tagnum] \
        } \
        $::SEC_ASN1_PRIVATE { \
            puts -nonewline $out [format "Private: %d " $tagnum] \
        }

    set codep $code;
    return 1;

}
proc prettyPrintObjectID {out  data len level raw} {
#    First print the Object Id in numeric format
    set rv [prettyIndent $out $level ];
    if {$rv < 0} {
        return $rv;
    }

    if {$len == 0} {
        return -1;
    }
    set dataobj [string range $data 0 [expr $len - 1] ]
    set obj [binary format H2a*a* 06 [::asn::asnLength $len] $dataobj]
    binary scan $obj H* obj_hex

    ::asn::asnGetObjectIdentifier obj oidalgo

#    Now try to look it up and print a symbolic version.
    set oiddata ""
    set oiddata [::pki::_oid_number_to_name $oidalgo]

    puts -nonewline $out "$oidalgo ";
    if { $oiddata != "" } {
        set i [string length $oiddata]
        set i [expr $i / 3]
        incr i
        set pc [expr $::prettyColumn + $i] 
        if {$pc > $::RIGHT_MARGIN } {
            set rv [prettyNewline $out];
            if {$rv < 0} {
                return $rv;
            }
        }
        set rv [prettyIndent $out $level];
        if {$rv < 0} {
            return $rv;
        }
	set oiddata1 [string toupper $oiddata]
	if {[info exists ::dn_fields($oiddata1)]} {
    	    set oiddata $::dn_fields($oiddata1)
        }
        puts -nonewline $out "\($oiddata\)";
    }

    set rv [prettyNewline $out];
    if {$rv < 0} {
        return $rv;
    }

    if {$raw} {
        set rv [prettyPrintLeaf $out data $len $level];
        if {$rv < 0} {
            return $rv;
        }
    }

    return 0;
}

proc prettyPrintTime {out str len level raw utc} {
    set rv [prettyPrintStringStart $out $str $len $level];
    if {$rv < 0} {
        return $rv;
    }

    puts -nonewline $out " ("

    incr len -1
    set str [string range $str 0 $len]
    if {$len == 11} {
	set tt_utc [clock scan $str -format {%y%m%d%H%M%S} -gmt $utc]
    } else {
	set tt_utc [clock scan $str -format {%y%m%d%H%M%SZ} -gmt $utc]
    }
    set dateSign [clock format $tt_utc]
    puts -nonewline $out "$dateSign"
    
    puts -nonewline $out ")"

    set rv [prettyNewline $out];
    if {$rv < 0} {
        return $rv;
    }

    incr len
    if {$raw} {
        set rv [prettyPrintLeaf $out str $len $level];
        if {$rv < 0} {
            return $rv;
        }
    }

    return 0;
}

proc prettyPrintItem {out data_var lendata lv  raw} {
    upvar 1 $data_var data
    set orig $lendata
    set tdata 0
	set slen 0
	set code ""
    while { $lendata > 0} {
	set slen1  [prettyPrintTag $out data $lendata code $lv $raw ]
        if {$slen1 < 0} {
            return $slen1;
        }
        set data [string range $data $slen1 end]
	set lendata [expr $lendata - $slen1]
	
        set lenLen [prettyPrintLength $out data $lendata slen indefinite $lv $raw]
        if {$lenLen < 0} {
            return $lenLen;
        }
        set data [string range $data $lenLen end]
	if {$slen > $lendata} {
	    return -1
	}
	
	set lendata [expr $lendata - $lenLen]

	if { [expr $code & $::SEC_ASN1_CONSTRUCTED]} {
            if {$slen > 0 || $indefinite} {
		set lv1 $lv
		incr lv1
		if {$slen == 0} {
		    set slen [prettyPrintItem $out data $orig $lv1 $raw];
		} else {
		    set slen [prettyPrintItem $out data $slen $lv1 $raw];
		}
		set lendata [expr $lendata - $slen]

                if {$slen < 0} {
                    return $slen;
                }
            }
        } elseif {$code == 0} {
            if {$slen != 0 || $lenLen != 1} {
                return -1;
            }
            break;
        } else {
	    set class [format "0x%02x" $code]
            switch -- $class \
                $::SEC_ASN1_PRINTABLE_STRING - $::SEC_ASN1_IA5_STRING - $::SEC_ASN1_VISIBLE_STRING - $::SEC_ASN1_UTF8_STRING - $::SEC_ASN1_NUMERIC_STRING { \
            	    set lv1 $lv; \
            	    incr lv1; \
                    set rv [prettyPrintString $out $data $slen $lv1 $raw]; \
                    if {$rv < 0} { \
                        return $rv; \
                    } \
                } \
                $::SEC_ASN1_UTC_TIME { \
            	    set lv1 $lv; \
            	    incr lv1; \
                    set rv [prettyPrintTime $out $data $slen $lv1 $raw 0]; \
                    if {$rv < 0} { \
                        return $rv; \
                    } \
                } \
                $::SEC_ASN1_GENERALIZED_TIME { \
            	    set lv1 $lv; \
            	    incr lv1; \
                    set rv [prettyPrintTime $out $data $slen $lv1 $raw 1]; \
                    if {$rv < 0} { \
                        return rv; \
                    } \
                } \
                $::SEC_ASN1_OBJECT_ID { \
            	    set lv1 $lv; \
            	    incr lv1; \
                    set rv [prettyPrintObjectID $out $data $slen $lv1 $raw]; \
                    if {$rv < 0} { \
                        return $rv; \
                    } \
                } \
                $::SEC_ASN1_BOOLEAN - $::SEC_ASN1_INTEGER - $::SEC_ASN1_BIT_STRING - $::SEC_ASN1_OCTET_STRING - $::SEC_ASN1_NULL - $::SEC_ASN1_ENUMERATED - $::SEC_ASN1_T61_STRING - $::SEC_ASN1_UNIVERSAL_STRING - $::SEC_ASN1_BMP_STRING - default { \
            	    set lv1 $lv; \
            	    incr lv1; \
                    set rv  [prettyPrintLeaf $out data $slen $lv1]; \
                    if {$rv < 0} { \
                        return $v; \
                    } \
                }

    	    set data [string range $data $slen end]
	    set lendata [expr $lendata - $slen]
        }
    }

    set rv [prettyNewline $out];

    set ldata [expr $orig - $lendata]

    return [expr $orig - $lendata]

}

proc DER_PrettyPrint {fdout deritem raw} {
    set ::prettyColumn -1;
    set len_deritem [string length $deritem]
    puts "LEN=$len_deritem"
    set rv [prettyPrintItem $fdout deritem $len_deritem 0 $raw];
    if {$rv < 0} {
	puts "Bad ASN1-structure"
        return -1;
    }
    return 0;
}
set ret [DER_PrettyPrint $fdout $data $raw]
if {$fdout != "stdout"} {
    close $fdout
}
