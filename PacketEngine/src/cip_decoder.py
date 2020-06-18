"""
Copyright 2019 Southern California Edison
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

from typing import List, Union

import stix2
import stix2.exceptions

from src.enip_decoder import EnipHeader, Cip, CipData, CipConnectionManager


class CIPDecoder:
    def __init__(self, decoder):
        self.decoder = decoder

    def decode(self, pyshark_packet):
        # type: ('pyshark.packet.packet.Packet') -> List[Union[EnipHeader, Cip, CipData, CipConnectionManager]]
        """

        :rtype: List[Union[EnipHeader, Cip, CipData, CipConnectionManager]]
        :type pyshark_packet: pyshark.packet.packet.Packet
        """
        # refargs, refobjects = self.decoder.decode(pyshark_packet)
        refobjects = []
        highest, layers = self.decoder.get_layers(pyshark_packet)
        if 'enip' in layers:
            values = layers['enip']
            try:
                enipargs = self.fix_enip_values(**values)
                e = EnipHeader(**enipargs)
                # refobjects[str(self.decoder.refcount)] = e
                refobjects.append(e)
                self.decoder.refcount += 1
            except stix2.exceptions.AtLeastOnePropertyError as e:
                print(e)
                print(values)
                print(pyshark_packet)
        if 'cip' in layers:
            cip_vals = layers['cip']
            try:
                cipargs = self.fix_cip_values(**cip_vals)
                c = Cip(**cipargs)
                refobjects.append(c)
                self.decoder.refcount += 1
            except stix2.exceptions.AtLeastOnePropertyError as e:
                print(e)
                print(cip_vals)
                print(pyshark_packet)
        if 'cipcls' in layers:
            vals = layers['cipcls']
            try:
                clsargs = self.fix_enip_values(**vals)
                if len(clsargs):
                    cipclass = CipData(**clsargs)
                    refobjects.append(cipclass)
                    self.decoder.refcount += 1
            except stix2.exceptions.AtLeastOnePropertyError as e:
                print(e)
                print(vals)
        if 'cipcm' in layers:
            cm_vals = layers['cipcm']
            # print(cm_vals)
            try:
                cmargs = self.fix_cip_values(**cm_vals)
                cm = CipConnectionManager(**cmargs)
                # print(cm)
                refobjects.append(cm)
                self.decoder.refcount += 1
            except stix2.exceptions.AtLeastOnePropertyError as e:
                print(e)
                print(cm_vals)
                print(pyshark_packet)
        return refobjects

    @staticmethod
    def fix_enip_values(**kwargs):
        """

        :param kwargs:
        :type kwargs: Union[Dict[str, pyshark.packet.fields.LayerFieldsContainer], Dict[str, Union[int, str]]]
        :return:
        :rtype: Union[Dict[str, pyshark.packet.fields.LayerFieldsContainer], Dict[str, Union[int, str]]]
        """
        ret = {}
        for k, v in kwargs.items():
            if k == 'time' or k == 'level' or k == 'response_to':
                continue
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

    @staticmethod
    def fix_cip_values(**cip_vals):
        """

        :param cip_vals:
        :type cip_vals: Union[Dict[str, pyshark.packet.fields.LayerFieldsContainer], Dict[str, Union[int, str]]]
        :return:
        :rtype: Union[Dict[str, pyshark.packet.fields.LayerFieldsContainer], Dict[str, Union[int, str]]]
        """
        ret = {}
        for k, v in cip_vals.items():
            if k == 'time' or k == 'level' or k == 'response_to':
                continue
            if k == 'rr':
                ret['cip_response'] = int(v, base=16)
            elif k == 'sc':
                ret['cip_service'] = int(v, base=16)
            elif isinstance(v, str):
                if '0x' in v:
                    ret[k] = int(v, base=16)
                elif ':' in v:
                    ret[k] = ''.join(v.split(':'))
                else:
                    try:
                        ret[k] = int(v, base=10)
                    except ValueError:
                        ret[k] = v
            else:
                ret[k] = v
        return ret
