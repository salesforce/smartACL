## Changelog
#### v3.0
- smartCompare now support Capirca policies
- smartCompare: now you can ignore specific rules in the comparison (like denies)
- smartCompare: now you can ignore shadowed rules in the source policy
- smartLog: now you can ignore to check an ACL if it contains specific text
- Link: bug fixed when using a specific destination port
- Added documentation about how to use Link/smartACL as a module (API)
- Several small fixes

#### v2.0b
- There was a bug in smartACL with rules like "permit tcp any any" where any "permit IP X Y" matched by mistake

#### v2.0a
- smartACL now support to work with 0.0.0.0/32
- Small bug fixes

#### v2.0
- Support for Capirca Policy files
- Adding to smartLog the possibility to check the whole ACL instead of diff file

#### v1.0
- Initial commit
