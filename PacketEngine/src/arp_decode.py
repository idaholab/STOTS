from stix2 import NetworkTraffic, properties, CustomExtension

"""
"layers": {
        "frame": {
          "frame.encap_type": "1",
          "frame.time": "Feb  6, 2018 10:30:39.048369000 MST",
          "frame.offset_shift": "0.000000000",
          "frame.time_epoch": "1517938239.048369000",
          "frame.time_delta": "0.071276000",
          "frame.time_delta_displayed": "0.071276000",
          "frame.time_relative": "44.783161000",
          "frame.number": "298",
          "frame.len": "60",
          "frame.cap_len": "60",
          "frame.marked": "0",
          "frame.ignored": "0",
          "frame.protocols": "eth:ethertype:arp"
        },
        "eth": {
          "eth.dst": "ff:ff:ff:ff:ff:ff",
          "eth.dst_tree": {
            "eth.dst_resolved": "Broadcast",
            "eth.addr": "ff:ff:ff:ff:ff:ff",
            "eth.addr_resolved": "Broadcast",
            "eth.lg": "1",
            "eth.ig": "1"
          },
          "eth.src": "00:0c:29:b6:ad:47",
          "eth.src_tree": {
            "eth.src_resolved": "Vmware_b6:ad:47",
            "eth.addr": "00:0c:29:b6:ad:47",
            "eth.addr_resolved": "Vmware_b6:ad:47",
            "eth.lg": "0",
            "eth.ig": "0"
          },
          "eth.type": "0x00000806",
          "eth.padding": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
        },
        "arp": {
          "arp.hw.type": "1",
          "arp.proto.type": "0x00000800",
          "arp.hw.size": "6",
          "arp.proto.size": "4",
          "arp.opcode": "1",
          "arp.src.hw_mac": "00:0c:29:b6:ad:47",
          "arp.src.proto_ipv4": "192.168.1.200",
          "arp.dst.hw_mac": "00:00:00:00:00:00",
          "arp.dst.proto_ipv4": "192.168.1.1"
        }
      }
    }
    dst_hw_mac, dst_proto_ipv4, hw_size, hw_type, level, opcode, proto_size, proto_type, src_hw_mac, src_proto_ipv4
    """


@CustomExtension(NetworkTraffic, 'x-arp-ext', [
    ('src_hw_mac', properties.StringProperty(required=True)),
    ('dst_hw_mac', properties.StringProperty(required=True)),
    ('src_proto_ipv4', properties.StringProperty(required=True)),
    ('dst_proto_ipv4', properties.StringProperty(required=True)),
    ('hw_size', properties.StringProperty(required=True)),
    ('hw_type', properties.StringProperty(required=True)),
    ('level', properties.StringProperty(required=True)),
    ('opcode', properties.StringProperty(required=True)),
    ('proto_size', properties.StringProperty(required=True)),
    ('proto_type', properties.StringProperty(required=True)),
    ('isgratuitous', properties.StringProperty())
])
class ArpPacket:
    pass
