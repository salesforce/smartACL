firewall {
    family inet {
        filter test {
            term icmp {
                /* allows permitted icmp */
                from {
                    protocol icmp;
                    fragment-offset 0;
                }
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                }
                then {
                    policer icmp;
                    accept;
                }
            }
            /* Next 2 line shouldn't be imported but shouldn't crash the parser */
            term permit-PUBLIC-BGP-PEERS {
                from {
                    source-prefix-list {
                        PL_BGP_PEERS;
                    }
                    protocol tcp;
                    destination-port 179;
                }
                then {
                    count permit-bgp-peers;
                    accept;
                }
            }
            term testt1 {
                from {
                    source-address {
                        10.0.0.0/24;
                        10.0.2.1;
                    }
                    destination-address {
                        10.0.1.0/24;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then {
                }
            }


            term testt1 {
                from {
                    source-address {
                        2001:0db8:85a3:0000:0000:8a2e:0370:7334;
                    }
                    destination-address {
                        2001:0db8:85a3:0000:0000:8a2e:0370:7332;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then {
                    accept;
                }
            }

            term testt1 {
                from {
                    source-address {
                        10.0.0.0/24;
                        10.0.2.1;
                    }
                    destination-address {
                        10.0.1.0/24;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then {
                    accept;
                }
            }
            /*
            ** Just a comment in the middle
            */
            term testt2 {
                from {
                    source-address {
                        10.0.0.192/26;
                    }
                    destination-address {
                        10.0.1.0/24;
                    }
                    protocol tcp;
                    destination-port [ 21 20 22 ];
                }
                then {
                    accept;
                }
            }
            term testt3 {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                    destination-address {
                        10.0.0.0/8;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then {
                    discard;
                }
            }
            term testt4 {
                from {
                    source-address {
                        10.0.0.0/24;
                    }
                    destination-address {
                        10.0.2.0/24;
                    }
                    protocol tcp;
                }
                then {
                    accept;
                }
            }
            term testt5 {
                from {
                    source-address {
                        10.0.1.0/24;
                    }
                    destination-address {
                        10.0.1.0/26;
                    }
                    protocol tcp;
                    destination-port 80;
                }
                then {
                    accept;
                }
            }
            term testt6 {
                from {
                    source-address {
                        10.0.1.128/25;
                    }
                    destination-address {
                        10.0.1.0/26;
                    }
                    protocol tcp;
                    destination-port 443;
                }
                then {
                    accept;
                }
            }

            inactive term test_inactive {
                from {
                    source-address {
                        10.0.1.128/25;
                    }
                    destination-address {
                        10.0.1.0/26;
                    }
                    protocol tcp;
                    destination-port 443;
                }
                then {
                    accept;
                }
            }

        }
    }
}
