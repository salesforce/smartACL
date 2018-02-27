## Using Link as a module (API)

Link can be used as a Python module easily, allowing its integration with any other application. Link only would need the flow you want 
to check, within which files and with which options.


### Working with Link directly
We can use Link to check if a specific flow is allowed or not. We could iterate this process as many times as we want.

- The method to use Link functionality is **_link_**
- This method will require four positional paramters:
    - Source IP
    - Destination IP
    - Python list with file/s to check
    - Python dictionary with any parameter you want to use

The dictionary used as parameter could contain (key/value)
- _key_: proto, _value_: character 
- _key_: sport, _value_: character (it could contain more than one, separating each value with ',' but it's NOT a Python list)
- _key_: dport, _value_: character (it could contain more than one, separating each value with ',' but it's NOT a Python list)
- _key_: matchanyport, _value_: True/False
- _key_: showdenyall, _value_: True/False (this is not used to check if the result is "printed" or not, but to ignore or not specific rules)
- _key_: hideallowall, _value_: True/False (this is not used to check if the result is "printed" or not, but to ignore or not specific rules)
- _key_: showallmatches, _value_: True/False 
- _key_: acltype, _value_: character
- _key_: summarized, _value_: True/False (not useful as a module)
- _key_: capircadef, _value_: character
- _key_: nooutput, _value_: True/False

You can check the explanation of each of these parameters in the help or in the README part of the "Operational Information" section.

The **returned** value will be a Python dictioanry where:
- Key: Name of the file with a match
- Value: Python list with rule _get_rule_ output. This is a list with the following values:
    - Name
    - Source Address
    - Destination Address
    - Destination Port
    - Source Port
    - Protocol
    - Permit (True/False)
    - Wildcard (True/False)
    - Source Name
    - Destination Name
    - Comment


### Example of Link as module

```
from link import link

# This is my ACL file, in this case I'll use a Cisco ACL
my_acl = 'test_acl_link.acl'

# I would like to check if 1.2.3.4 can talk with 8.8.8.8 for tcp port 80
# Although I have only one file, I need to pass it as Python list
sourceIP = '1.2.3.4'
destIP = '10.0.0.1'
opts = {}
opts['proto'] = 'tcp'
opts['dport'] = '80'
result = link(sourceIP, destIP, [my_acl], opts)
```


This will be the output:
```
############ CHECKING FLOW ############
1.2.3.5 -> 10.0.0.1 Dest Port:  80 Source Port:  0 Protocol: tcp
############## ACL CHECK ##############
Processing file: test_acl_link.acl                                - HIT!!
Rule number: 5
Rule name: permit tcp host 1.2.3.5 host 10.0.0.1 eq 80
Source Address: 1.2.3.5/255.255.255.255
Destination Address: 10.0.0.1/255.255.255.255
Destination Port: 80
Source Port: 0
Protocol: tcp
Wildcard: False
Action: PERMIT
```

And the content of result would be:

```
{'test_acl_link.acl': [['permit tcp host 1.2.3.5 host 10.0.0.1 eq 80', '1.2.3.5/255.255.255.255', '10.0.0.1/255.255.255.255', '80', '0', 'tcp', True, False, '', '', '']]}
```

## Using directly smartACL Policies to check a flow (embedded) Link

Maybe you would like to have more control over what you want to do with the policies, in this case, it could be more interesting to use
directly Link with smartACL Policies.
    
Link will work only with smartACL policies, so in this case, the first thing to do, would be to convert the policy you want to check into smartACL policy.

###Importing policies into smartACL

For the time being, there are three different modules that translate ACL/policies into smartACL policy format:

- link_cisco.py will translate Cisco ACL through the method **_acl_parser_**
- link_juniper.py will translate Juniper ACL through the method **_jcl_parser_**
- link_pol.py will translate Capirca policies through the method **_pol_parser_**

You can check the documentation of each method to see what parameters would be needed.

###Working with smartACL policies
After we have imported the policies, we can now use Link to check if a specific flow is allowed or not. We could iterate this process as many times as we want.

- The method to use Link method from smartACL is **_link_**
- This method will require five positional paramters:
    - Source IP
    - Destination IP
    - Destination Port
    - Source Port
    - Protocol
- And you have 8 optional parameters to have full control over the flow to check

Please, check the documentation inside _link_def.py_ for this method and the explanation of each parameter.

### Example of Link as embedded
``` 
from linkdef import FWPolicy
from link_cisco import acl_parser

# This is my ACL file, in this case I'll use a Cisco ACL
my_acl = 'test.acl'

# Define my smartACL policy
policy = FWPolicy('My Policy', my_acl)

# Import the Cisco ACL file into the smartACL policy format
acl_parser(my_acl, policy)

sourceIP = '1.2.3.4'
destIP = '8.8.8.8'
proto = 'tcp'
sport = '0'
dport = '80'
result = policy.link(sourceIP, destIP, dport, sport, proto)

# Result would be [13] that it's the rule number in smartACL policy
# We can prin't the rule
policy.print_rule(result[0])

'''
This would be the output

Rule number: 13
Rule name: permit tcp host 1.2.3.4 any eq 80
Source Address: 1.2.3.4/255.255.255.255
Destination Address: 0.0.0.0/0.0.0.0
Destination Port: 80
Source Port: 0
Protocol: tcp
Wildcard: False
Action: PERMIT
'''

# Or we can store all the information of the rule as a Python List
rule = policy.get_rule(result[0])
# rule[0] -> name
# rule[1] -> source address
# rule[2] -> destination address
# rule[3] -> destination port
# rule[4] -> source port
# rule[5] -> protocol
# rule[6] -> permit (True/False)
# rule[7] -> wildcard (True/False)
# rule[8] -> source name
# rule[9] -> dest name
# rule[10] -> comment

```