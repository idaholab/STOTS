"""
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
from typing import List, Union

import stix2
import stix2.exceptions

from src.dnp3_stix import DNP3Header


class DNP3Decoder:
    def __init__(self, decoder):
        self.decoder = decoder

    def decode(self, pyshark_packet):
        # type: ('scapy.packet.packet.Packet') -> List[Union[DNP3Header, Transport, ApplicationRequest, ApplicationIIN, ApplicationResponse, ApplicationControl]]
        """
        :rtype: List[Union[Datalink, Transport, Application]]
        :type scapy.packet.packet.Packet
        :param scapy_packet:
        :return:
        """

        refobjects = []

        highest, layers = self.decoder.get_layers(pyshark_packet)
        # if scapy_packet.haslayer(DNP3_Lib.DNP3) == 1:
        if 'dnp3' in layers:
            values = layers['dnp3']
            try:
                dnp3args = self.fix_dnp3_values(**values)
                dn = DNP3Header(**dnp3args)
                # dn = DNP3Header(**values)       # debug
                refobjects.append(dn)
                self.decoder.refcount += 1
            except stix2.exceptions.AtLeastOnePropertyError as dn:
                print(dn)
                print(values)
                print(pyshark_packet)

        return refobjects

    @staticmethod
    def fix_dnp3_values(**kwargs):
        """

        :param kwargs:
        :type kwargs: Union[Dict[str, pyshark.packet.fields.LayerFieldsContainer], Dict[str, Union[int, str]]]
        :return:
        :rtype: Union[Dict[str, pyshark.packet.fields.LayerFieldsContainer], Dict[str, Union[int, str]]]
        """
        ret = {}
        for k, v in kwargs.items():
            # if k == 'time' or k == 'level' or k == 'response_to':
            # continue
            if isinstance(v, str):
                if '0x' in v:
                    ret[k] = int(v, base=16)
                elif ':' in v:
                    ret[k] = ''.join(v.split(':'))
                else:
                    ret[k] = int(v, base=10)
            else:
                ret[k] = v
        return ret
