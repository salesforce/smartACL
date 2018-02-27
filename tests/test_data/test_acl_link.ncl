permit icmp 10.0.0.0 0.0.0.255 10.0.0.0 0.0.0.255
permit udp 10.0.0.0 0.0.0.255 10.0.0.0 0.0.0.255 53
permit tcp 10.0.0.0 0.0.0.255 any eq 80
permit udp any host 8.8.8.8 eq 53
permit tcp 10.231.69.128 0.0.0.127 10.0.0.0 0.0.0.255 eq 7080
permit tcp 10.231.69.128 0.0.0.63 10.0.0.64 0.0.0.63 eq 7080
permit tcp 10.231.69.128 0.0.0.127 10.0.0.128 0.0.0.63 eq 7080
permit tcp 10.231.69.128 0.0.0.127 10.0.0.192 0.0.0.63 eq 7080
permit tcp 10.231.69.128 0.0.0.127 eq 7080 10.0.0.192 0.0.0.255 eq 7080
permit tcp host 10.231.69.150 host 10.0.0.1 range 100 200
permit tcp host 10.231.69.150 range 100 200 host 10.0.0.1
permit tcp host 10.231.69.150 10.0.0.0 0.0.0.255 8080
permit 6 host 10.231.69.150 10.0.0.0 0.0.0.255 8081
permit 17 host 10.231.69.150 10.0.0.0 0.0.0.255 8081
permit 1 host 10.231.69.150 10.0.0.0 0.0.0.255
permit tcp 10.0.0.0 0.0.0.255 182.17.73.0 8.64.4.0 eq 80
permit tcp 10.0.0.0 0.0.0.255 host 1.2.3.4 gt 7000
permit tcp 10.0.0.0 0.0.0.255 host 1.2.3.4 lt 8000
deny tcp host 1.2.3.4 neq 8080 any
permit tcp host 1.2.3.5 gt 7000 any
permit tcp host 1.2.3.5 lt 8000 any
permit tcp 10.0.0.0 0.0.0.255 host 1.2.3.4 neq 8080
permit host 10.0.0.1
deny ip any any log
