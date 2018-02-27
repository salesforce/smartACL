# Table of Contents
1. [Link: Introduction](#link-introduction)
2. [Link: RUNBOOKS](#link-runbooks)
3. [smartCompare: Introduction](#smartcompare-introduction)
4. [smartCompare: RUNBOOKS](#smartcompare-runbooks)
5. [smartShadow: Introduction](#smartshadow-introduction)
6. [smartShadow: RUNBOOKS](#smartshadow-runbooks)
7. [smartLog: Introduction](#smartlog-introduction)
8. [smartLog: RUNBOOKS](#smartlog-runbooks)


## Link: Introduction

Link allows to check flows in different ACLs format. For the time being Cisco, Force10 and Juniper are the ones supported.
Although it's possible for Link to parse the whole configuration, it's easier if the ACL configuration is contained in a specific file.
Link creates its own "rule database" parsing the ACL file and later, based on this parsing, will check if the flow (or flows) requested are permitted or denied.


#### Command Line
```
usage: link.py [-h] [--protocol PROTOCOL] [--sport SPORT] [--dport DPORT]
               [--match-any-range-port] [--showdenyall] [--hideallowall]
               [--showallmatches] [--acltype ACLTYPE] [--summarized]
               [--capircadef CAPIRCADEF] [--nooutput] [--debug]
               Source Destination [File [File ...]]

positional arguments:
  Source                Source IP/Network to check. Use 0.0.0.0 for ANY. You
                        can specify more than one source separating them by
                        "," (no spaces)
  Destination           Destination IP/Network to check. Use 0.0.0.0 for ANY.
                        You can specify more than one destination separating
                        them by "," (no spaces)
  File                  File or Directory to check the IPs (you can use * )

optional arguments:
  -h, --help            show this help message and exit
  --protocol PROTOCOL   Value ip/tcp/udp/icmp. IP by default.
  --sport SPORT         Source port. It could be a range (use - to separate
                        ports) (ANY by default).
  --dport DPORT         Destination port. It could be a range (use - to
                        separate ports) (ANY by default).
  --match-any-range-port
                        If a range is used for a port, then any match included
                        in the range is shown
  --showdenyall         Show matches with ANY ANY DENY
  --hideallowall        Hide matches with ANY ANY PERMIT
  --showallmatches      Show all matches instead of stopping with the first
                        found
  --acltype ACLTYPE     Specifiy the ACL type: acl,ncl,jcl,pol
  --summarized          Show only a summary for the flow/s requested
  --capircadef CAPIRCADEF
                        Capirca definitions directory
  --nooutput            Hide any output (useful as module)
  --debug
```

**_Source_**/**_Destination_**: They could be any of these values

- single IP: 10.0.0.1
- single Network: 10.0.0.0/8, 10.0.0.0/255.255.255.0
- List of IP and/or networks (use comma to separate NO spaces): 10.0.0.0/8,11.0.0.0/8

**_File_**: you can use wildcards to specify multiple files (*.acl) or files matching a specific criteria (*my_dc*.acl)

## Link: RUNBOOKS

### Check a single flow in one file
We want to check the following flow:

Source: _10.0.0.1_

Destination: _10.0.0.2_

In the file: _./tests/test_data/test_acl_link.ncl_

For: _80/TCP_

```
(smartacl-pypy) $ smartACL/link.py 10.0.0.1 10.0.0.2 ./tests/test_data/test_acl_link.ncl --protocol tcp --dport 80
############ CHECKING FLOW ############
10.0.0.1 -> 10.0.0.2 Dest Port:  80 Source Port:  0 Protocol: tcp
############## ACL CHECK ##############
Processing file: ./tests/test_data/test_acl_link.ncl                              - HIT!!
Rule number: 3
Rule name: permit tcp 10.0.0.0 0.0.0.255 any eq 80
Source Address: 10.0.0.0/0.0.0.255
Destination Address: 0.0.0.0/255.255.255.255
Destination Port: 80
Source Port: 0
Protocol: tcp
Wildcard: True
Action: PERMIT
```


### Check a single flow in several files
We want to check the following flow:

Source: _10.0.0.0/24_

Destination: _10.0.0.10_

In the file: all nexus ACL files in ./tests/test_data/_

For: _80/TCP_

```
(smartacl-pypy) $ smartACL/link.py 10.0.0.0/24 10.0.0.10 tests/test_data/*.ncl --protocol tcp --dport 80
############ CHECKING FLOW ############
10.0.0.0/24 -> 10.0.0.10 Dest Port:  80 Source Port:  0 Protocol: tcp
############## ACL CHECK ##############
Processing file: tests/test_data/test_acl_link.ncl                                - HIT!!
Rule number: 3
Rule name: permit tcp 10.0.0.0 0.0.0.255 any eq 80
Source Address: 10.0.0.0/0.0.0.255
Destination Address: 0.0.0.0/255.255.255.255
Destination Port: 80
Source Port: 0
Protocol: tcp
Wildcard: True
Action: PERMIT
```


### Check several flows in several files and showing all matches in each file
We want to check the following flows:

Source: _10.231.69.128/27, 1.2.3.4_

Destination: _10.0.0.1_

In the file: all nexus ACL files in ./tests/test_data/_

For: _7080/TCP_

```
(smartacl-pypy) $ smartACL/link.py 10.231.69.128/27,1.2.3.4 10.0.0.1 tests/test_data/*.ncl --protocol tcp --dport 7080 --showallmatches
############ CHECKING FLOW ############
10.231.69.128/27 -> 10.0.0.1 Dest Port:  7080 Source Port:  0 Protocol: tcp
############## ACL CHECK ##############
Processing file: tests/test_data/test_acl_link.ncl                                - HIT!!
Rule number: 5
Rule name: permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080
Source Address: 10.231.69.128/0.0.0.127
Destination Address: 10.0.0.0/0.0.0.255
Destination Port: 7080
Source Port: 0
Protocol: tcp
Wildcard: True
Action: PERMIT

Processing file: tests/test_data/test_acl_link.ncl                                - HIT!!
Rule number: 9
Rule name: permit tcp 10.231.69.128 0.0.0.127 eq 7080 10.0.0.192 0.0.0.255 eq 7080
Source Address: 10.231.69.128/0.0.0.127
Destination Address: 10.0.0.192/0.0.0.255
Destination Port: 7080
Source Port: 7080
Protocol: tcp
Wildcard: True
Action: PERMIT

############ CHECKING FLOW ############
1.2.3.4 -> 10.0.0.1 Dest Port:  7080 Source Port:  0 Protocol: tcp
############## ACL CHECK ##############
Processing file: tests/test_data/test_acl_link.ncl                                - HIT!!
Rule number: 19
Rule name: deny tcp host 1.2.3.4 neq 8080 any
Source Address: 1.2.3.4/0.0.0.0
Destination Address: 0.0.0.0/255.255.255.255
Destination Port: 0
Source Port: 0-8079,8081-65535
Protocol: tcp
Wildcard: True
Action: DENY
```


## smartCompare: Introduction
smartCompare compares two different ACLs identifying any difference between them. It supports Cisco, Juniper and Force10,
allowing comparing ACLs with different flavours.

#### Command Line
```
usage: smartACL.py --smartcompare --acl-old <ACL-FILE> --acl-new <ACL-FILE>

Optional arguments
--acl-old                           Old ACL file or directory to compare
--acl-new                           New ACL file or directory to compare
-s, --show-only-different           When comparing directories will show an output only with different files
-il, --ignore-line                  Ignore the following lines (ACL remark for Cisco or Term name for Juniper)
-is, --ignore-shadowed              smartCompare will perform a BASIC rule shadowing lookup and discard any found rule for the comparison
--ignoredeny                        Ignore DENY rules. (DANGEROUS, CAN'T SHOW FAKE RESULTS)
--capirca-dir                       Directory containing NETWORK.net and SERVICES.svc
--remarkasname                      Will use "remarks" as name of the rule for Cisco ACLs
--acltype                           Specifiy the ACL type: acl,ncl,jcl
-v, --verbose                       Verbose output
-d, --debug
-h, --help                          This message
```

- In case of using two directories to compare, smartCompare will compare files with the exactly same name in both.
- When acltype is not used, the file extension is used (.acl, .ncl, .jcl) to determine the ACL type (Cisco IOS, Cisco Nexus, Juniper)


## smartCompare: RUNBOOKS

### Comparing two ACLs

We want to compare the new ACL file *tests/test_data/test_acl_smartCompare2* with the old ACL file *tests/test_data/test_acl_smartCompare1*
```
(smartacl-pypy) $ smartACL/smartACL.py --smartcompare --acl-old tests/test_data/test_acl_smartCompare1 --acl-new tests/test_data/test_acl_smartCompare2 --acltype ncl

Processing file:  tests/test_data/test_acl_smartCompare1
Processing rule: 1 out of 4
Processing rule: 2 out of 4
Processing rule: 3 out of 4
Processing rule: 4 out of 4
------ SmartCompare ------
Number of lines in old policy (without remarks): 4
Number of lines in new policy (without remarks): 2

Number of rules shadowed in the new policy: 4

Number of rules NOT fully matched in the new policy: 0
Rules not fully matched from OLD policy:
```
### Output explanation

- ***Number of lines in old/new policy (without remarks)*** -> Total number of lines with "permit" or "deny" in the old/new file. All remarks and empty lines are excluded


- ***Number of rules shadowed in the new policy*** -> Number of lines shadowed/covered in the new file. Example

Old acl:
> permit 10.0.0.0 0.0.0.127 any eq 80

> permit 10.0.0.128 0.0.0.127 any eq 80

New acl:

> permit 10.0.0.0 0.0.0.255 any eq 80

in the new ACL file, the two /25 networks are shadowed/covered by the /24 in the new file

- ***Number of rules NOT fully matched in the new policy*** -> Number of lines that couldn't be fully matched in the new policy. Example:

Old acl:
> permit 10.0.0.0 0.0.0.255 any eq 80

New acl:
> permit 10.0.0.0 0.0.0.63 any eq 80

> permit 10.0.0.64 0.0.0.63 any eq 80

in the old ACL we have an /24 but in the new ACL file we have only two /26 networks, so still we are missing another two /26 to fully cover the /24 in the old ACL file.


### Comparing two directories
We want to compare all ACLs with the name matching the text "smartCompare1" followed by at least one character (smartCompare10, smartCompare11, etc.).
 The old ACLs are in _tests/test_data/_ and the new ones are in _tests/test_data2/_ and they are Juniper ACLs

```
(smartacl-pypy) $ smartACL/smartACL.py --smartcompare --acl-old tests/test_data/*smartCompare1?* --acl-new tests/test_data2/*smartCompare1?* --acltype jcl

Processing file:  tests/test_data/test_acl_smartCompare10
Processing rule: 1 out of 8
Processing rule: 2 out of 8
Processing rule: 3 out of 8
Processing rule: 4 out of 8
Processing rule: 5 out of 8
Processing rule: 6 out of 8
Processing rule: 7 out of 8
Processing rule: 8 out of 8
------ SmartCompare ------
Number of lines in old policy (without remarks): 6
Number of lines in new policy (without remarks): 6

Number of rules shadowed in the new policy: 4

Number of rules NOT fully matched in the new policy: 2
Rules not fully matched from OLD policy:
term testt5
term testt6

Processing file:  tests/test_data/test_acl_smartCompare11
Processing rule: 1 out of 6
Processing rule: 2 out of 6
Processing rule: 3 out of 6
Processing rule: 4 out of 6
Processing rule: 5 out of 6
Processing rule: 6 out of 6
------ SmartCompare ------
Number of lines in old policy (without remarks): 6
Number of lines in new policy (without remarks): 6

Number of rules shadowed in the new policy: 5

Number of rules NOT fully matched in the new policy: 1
Rules not fully matched from OLD policy:
term testt4

Processing file:  tests/test_data/test_acl_smartCompare12
Processing rule: 1 out of 12
Processing rule: 2 out of 12
Processing rule: 3 out of 12
Processing rule: 4 out of 12
Processing rule: 5 out of 12
Processing rule: 6 out of 12
Processing rule: 7 out of 12
Processing rule: 8 out of 12
Processing rule: 9 out of 12
Processing rule: 10 out of 12
Processing rule: 11 out of 12
Processing rule: 12 out of 12
------ SmartCompare ------
Number of lines in old policy (without remarks): 7
Number of lines in new policy (without remarks): 7

Number of rules shadowed in the new policy: 7

Number of rules NOT fully matched in the new policy: 0
Rules not fully matched from OLD policy:
```


## smartShadow: Introduction
smartShadow will look for rules shadowed and "unnecessary" in an ACL file.

There are two kind of shadow rule:
- Rules that have the same action permit/deny and shadow another rule. Example:

    rule1: permit 10.0.0.0/8 11.0.0.0/8

    rule2: permit 10.0.0.0/24 11.0.0.0/24

    rule2 is shadowed by rule1. It's NOT possible that any traffic match rule2 that not match rule1

- Rules having "deny" action, that shadow a "permit" rule. Example:

    rule1: deny 10.0.0.0/8 any

    rule2: permit 10.10.10.0/24 10.10.20.0/24

    rule2 is shadowed by rule1. It's NOT possible that any traffic match rule2 that not match rule1

Also, there are "unnecessary" rules. These rules can be removed and the same traffic will be permitted/denied. Example:

- Unnecessary rule:

    rule1: permit 10.0.0.0/24 11.0.0.0/24

    rule2: permit 10.0.0.0/8 11.0.0.0/8

    rule1 is not needed because the same flows matching rule1 will match rule2. The only reason to have these kind of rules could be related with performance.


#### Partially Shadowed
Juniper ACLs allow to have several IP/Networks in the source and/or destination. For example, this a term for a Juniper ACL:
```
term testt6 {
    from {
        source-address {
            10.0.0.0/24;
        }
        destination-address {
            10.0.1.0/26;
            12.0.1.0/26;
        }
        protocol tcp;
        destination-port 22;
    }
    then {
        accept;
    }
}
```
With these kind of ACLs, a "partial" shadow is possible. For example, we could have another term:
```
term testt5 {
    from {
        source-address {
            10.0.0.0/24;
        }
        destination-address {
            10.0.1.0/26;
        }
        protocol tcp;
        destination-port 22;
    }
    then {
        accept;
    }
}
```
In this scenario, we assume that testt5 is being processed before testt6, so this last one is SHADOWED PARTIALLY and smartShadow will detect this situation.

#### Command Line
```
usage: smartACL.py --smartshadow --acl-old <ACL-FILE>

Optional arguments
--acl-old                           ACL file
--remarkasname                      Will use "remarks" as name of the rule for Cisco ACLs
--acltype                           Specifiy the ACL type: acl,ncl,jcl
-v, --verbose                       Verbose output
-d, --debug
-h, --help                          This message
```

- When acltype is not used, the file extension is used (.acl, .ncl, .jcl) to determine the ACL type (Cisco IOS, Cisco Nexus, Juniper)


## smartShadow: RUNBOOKS

### Looking for shadowed rules in Cisco Nexus ACL file
We want to check if there is any shadowed rules in the ACL file tests/test_data/test_acl_smartShadow2

```
(smartacl-pypy) $ smartACL/smartACL.py --smartshadow --acl-old tests/test_data/test_acl_smartShadow2 --acltype ncl

Processing file:  tests/test_data/test_acl_smartShadow2
Checking duplicated shadowing...
Number of rules to process: 5
Processing rule 1 of 5
Processing rule 2 of 5
Processing rule 3 of 5
Processing rule 4 of 5
Processing rule 5 of 5
Checking DENY shadowing...

----------- Summary -----------
List of rules that can be removed (same flow allow/deny shadowed): ( 2 )

  Rule:
     permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127
  Fully matched with rule/s:
     permit tcp 10.230.0.0 0.0.0.127 10.240.0.0 0.0.0.127
------
  Rule:
     permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080
  Fully matched with rule/s:
     permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.63 eq 7080
     permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.127 eq 7080
     permit tcp 10.231.69.128 0.0.0.127 10.0.0.64 0.0.0.63 eq 7080
------

List of rules that can be removed (DENY shadowing): ( 0 )

-------------------
```

- Because the rules are processed in order, if you check the file _tests/test_data/test_acl_smartShadow2_ you will see the rule: _permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080_
before the other three rules that "shadowed" this one. For cases like this one, the correct thing to do it to remove the three rules matching the "wider" rule.


### Looking for shadowed rules in Juniper ACL file
We want to check if there is any shadowed rules in the ACL file tests/test_data/test_acl_smartShadow10 with Juniper format.

```
(smartacl-pypy) $ smartACL/smartACL.py --smartshadow --acl-old tests/test_data/test_acl_smartShadow10 --acltype jcl

Processing file:  tests/test_data/test_acl_smartShadow10
Checking duplicated shadowing...
Number of rules to process: 18
Processing rule 1 of 18
Processing rule 2 of 18
Processing rule 3 of 18
Processing rule 4 of 18
Processing rule 5 of 18
Processing rule 6 of 18
Processing rule 7 of 18
Processing rule 8 of 18
Processing rule 9 of 18
Processing rule 10 of 18
Processing rule 11 of 18
Processing rule 12 of 18
Processing rule 13 of 18
Processing rule 14 of 18
Processing rule 15 of 18
Processing rule 16 of 18
Processing rule 17 of 18
Processing rule 18 of 18
Checking DENY shadowing...
Processing DENY rule 10
Processing DENY rule 11
Processing DENY rule 12
Processing DENY rule 13

----------- Summary -----------
List of rules that can be removed (same flow allow/deny shadowed): ( 3 )

  Rule:
     term testt2a
  Fully matched within compound rule:
     term testt1 Source IP: 10.0.0.0/255.255.255.0 Destination IP:  10.0.1.0/255.255.255.0
------
  Compound Rule:
     term testt2b Source IP: 11.0.0.192/255.255.255.192 Destination IP: 10.0.1.0/255.255.255.0
  Partially matched within compound rule:
     term testt1 Source IP: 11.0.0.0/255.255.255.0 Destination IP:  10.0.1.0/255.255.255.0
------
  Compound Rule:
     term testt6 Source IP: 10.0.0.0/255.255.255.0 Destination IP: 10.0.1.0/255.255.255.192
  Partially matched within compound rule:
     term testt1 Source IP: 10.0.0.0/255.255.255.0 Destination IP:  10.0.1.0/255.255.255.0
------

List of rules that can be removed (DENY shadowing): ( 2 )

  Rule:
     term testt5
  Fully matched within compound rule:
     term testt3 Source IP: 10.0.0.0/255.0.0.0 Destination IP:  10.0.0.0/255.0.0.0
     term testt3 Source IP: 10.0.0.0/255.0.0.0 Destination IP:  11.0.0.0/255.0.0.0
------
  Compound Rule:
     term testt6 Source IP: 10.0.0.0/255.255.255.0 Destination IP: 10.0.1.0/255.255.255.192
  Partially matched within compound rule:
     term testt3 Source IP: 10.0.0.0/255.0.0.0 Destination IP:  10.0.0.0/255.0.0.0
------
-------------------
```

- This ACL has several permits and several denies. Although the file only contains 6 terms, almost all terms contain more tha one source and/or destination.
This is the reason why we can see processing 18 rules message.
- In Juniper "Partial Match" is possible, because only part of the rule could be matched.


## smartLog: Introduction
smartLog analyzes a diff file from two (or more) ACL files, showing real removals, shadow removals or just lines reordered.
It's very important to keep in mind that smartLog can't guess the information that is not included in the diff file.
Usually a diff file has a "context" if this is very small, smartLog could show fake results.

#### Command Line
```
usage: smartACL.py --smartlog --diff-file <DIFF_FILE> [-r] [-p] [-f]

Optional arguments
--diff-file                         Diff file
-il, --ignore-line                  Ignore ACL with the following remark
-r, --print-removed-rules-by-file   Print all rules by file that they are really going to be removed
-f, --print-removed-rules-by-flow   Print all rules by flow that they are really going to be removed
-p, --print-add-matches             Print ADD matches for DEL lines
-n, --no-check-fakes                NO check for twin rules (exactly the same - and + in the diff file)
-a, --acl-dir                       Directory with ALL ACLs to compare diff file
--remarkasname                      Will use "remarks" as name of the rule for Cisco ACLs
--acltype                           Specifiy the ACL type: acl,ncl,jcl
-v, --verbose                       Verbose output
-d, --debug
-h, --help                          This message
```
- smartLog could process a diff file containing more than file diffs. If this is the case, the options _-r_ and _-f_ become useful.
The main difference between them is how the information is represented, the "core" part is exactly the same

- smartLog only works with diff files generated from Cisco ACLs files (IOS or Nexus)

- smartLog can check the diff files agains the current ACL using the parameter --acl-dir. In this case the, it's mandatory that all ACLs files
contained in the diff file are located in the directory specified by --acl-dir.

## smartLog: RUNBOOKS

### Check diff file per flow
Review with the diff file _tests/test_data/test_acl_splitted.diff_ which flows are removed. Show the real removed flows per flow.

```
(smartacl-pypy) $ smartACL/smartACL.py --smartlog --diff-file tests/test_data/test_acl_splitted.diff
Number of lines to be added (+):  2
-------------------------------------------
Number of remarks: 0
Number of blank lines: 0


Number of lines to be removed (-):  1
-------------------------------------------------
Number of lines reordered: 0
Number of lines shadowed: 0
Number of remarks removed: 0
Number of blank lines removed: 0

Number of FLOWS REALLY removed: 1
ACL: permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080
- tests/test_data/test_acl_splitted.diff
```

- Removed flows are shown grouped by flow.


### Check diff file per file
Review with the diff file _tests/test_data/test_acl_splitted.diff_ which flows are removed. Show the real removed flows per flow.

```
(smartacl-pypy) $ smartACL/smartACL.py --smartlog --diff-file tests/test_data/test_acl_splitted.diff -r
Number of lines to be added (+):  2
-------------------------------------------
Number of remarks: 0
Number of blank lines: 0


Number of lines to be removed (-):  1
-------------------------------------------------
Number of lines reordered: 0
Number of lines shadowed: 0
Number of remarks removed: 0
Number of blank lines removed: 0

Number of FLOWS REALLY removed: 1
ACL: tests/test_data/test_acl_splitted.diff
- permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080
```

- Removed flows are shown grouped by file.


### Check diff file against a directory with all the ACLs
Some times we will have a diff file without enough context to know if a change has a real impact or not. For example, we could have a diff file like:
```
 permit ip 10.0.0.0/8 any eq http
 permit udp any host 8.8.8.8 eq 53
 permit tcp host 1.2.3.5 host 10.0.0.1 eq 80
-permit tcp 10.231.69.128/26 10.0.0.0/28 eq 7080
 permit tcp 10.231.69.128/26 10.0.0.64 255.255.255.240 eq 7080
 permit tcp 10.231.69.128/25 10.0.0.128/26 eq https
 permit tcp 10.231.69.128/25 10.0.0.192/26 eq 7080
```
Within this context it seems that the rules removed would have a real impact. But, what if this is just part of a 1000 lines ACL and we
have another line before "far" from this one like: "permit tcp 10.231.69.0 any".

In this scenario, removing this line won't have any real impact. But to check this we would need the whole ACL. For this, we can use smartLog
with the parameter _--acldir <directory with all ACLs from the diff file>_ 

```
(smartacl-pypy) $ smartACL/smartACL.py --smartlog --diff-file tests/test_data/test_acl_splitted.diff --acldir tests/acl_dir
```

If the diff file is a valid unified diff, will contain the name of each file modifed before the modification and smartLog will use this
information to compare each modification against the real ACL.