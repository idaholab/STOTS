"""
Copyright 2019 Southern California Edison
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

import logging
from stix2 import ExternalReference, GranularMarking
from stix2.base import _STIXBase
from stix2.properties import BooleanProperty, IDProperty, IntegerProperty, ListProperty, Property, ReferenceProperty, \
    StringProperty, TimestampProperty, TypeProperty
from stix2.utils import NOW
from collections import OrderedDict
from stix2.properties import ObservableProperty

logging.getLogger(__name__)

class DeviceProperty(Property):

    def __init__(self, type_str):
        self.required_prefix = type_str + "--"
        super(DeviceProperty, self).__init__()


class StixObservedData(_STIXBase):
    _type = 'observed-data'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type="device_ref")),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('first_observed', TimestampProperty(required=True)),
        ('last_observed', TimestampProperty(required=True)),
        ('number_observed', IntegerProperty(required=True)),
        ('objects', ObservableProperty()),
        ('revoked', BooleanProperty()),
        ('labels', ListProperty(StringProperty)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type="marking-definition"))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('device_ref', DeviceProperty('device'))
    ])
