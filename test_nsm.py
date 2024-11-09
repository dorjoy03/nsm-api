import ctypes
import fcntl
import typing
import time
import unittest

import cbor2
from ioctl_opt import IOC, IOC_READ, IOC_WRITE

NSM_RESPONSE_MAX_SIZE = 0x3000

class IOVec(ctypes.Structure):
    iov_base: ctypes.c_void_p
    iov_len: ctypes.c_size_t

    _fields_ = [
        ('iov_base', ctypes.c_void_p),
        ('iov_len', ctypes.c_size_t)
    ]

class NSMStruct(ctypes.Structure):
    request: IOVec
    response: IOVec

    _fields_ = [
        ('request', IOVec),
        ('response', IOVec)
    ]

def decode_nsm_response(msg: NSMStruct):
    buf = bytearray(msg.response.iov_len)
    ptr = (ctypes.c_char * msg.response.iov_len).from_buffer(buf)
    ctypes.memmove(ptr, msg.response.iov_base, msg.response.iov_len)
    ret = cbor2.loads(buf)
    return ret

def send_nsm_req(fh: typing.TextIO, buf: bytes):
    req =  ctypes.create_string_buffer(buf, len(buf))
    rsp = (NSM_RESPONSE_MAX_SIZE * ctypes.c_uint8)()

    nsm_msg = NSMStruct()
    nsm_msg.request = IOVec(
        ctypes.cast(ctypes.byref(req), ctypes.c_void_p),
        len(req)
    )
    nsm_msg.response = IOVec(
        ctypes.cast(ctypes.byref(rsp), ctypes.c_void_p),
        len(rsp)
    )
    op = IOC(IOC_READ | IOC_WRITE, 0x0A, 0x00, ctypes.sizeof(NSMStruct))
    fcntl.ioctl(fh, op, nsm_msg)
    return decode_nsm_response(nsm_msg)

def lock_pcr(fh: typing.TextIO, ind: int):
    buf = cbor2.dumps({
        'LockPCR': {
            'index': ind
        }
    })
    return send_nsm_req(fh, buf)

def lock_pcrs(fh: typing.TextIO, range: int):
    buf = cbor2.dumps({
        'LockPCRs': {
            'range': range
        }
    })
    return send_nsm_req(fh, buf)

def extend_pcr(fh: typing.TextIO, ind: int, data: bytes):
    buf = cbor2.dumps({
        'ExtendPCR': {
            'index': ind,
            'data': data
        }
    })
    return send_nsm_req(fh, buf)

def describe_pcr(fh: typing.TextIO, ind: int):
    buf = cbor2.dumps({
        'DescribePCR': {
            'index': ind
        }
    })
    return send_nsm_req(fh, buf)

def describe_nsm(fh: typing.TextIO):
    buf = cbor2.dumps('DescribeNSM')
    return send_nsm_req(fh, buf)

def get_random(fh: typing.TextIO):
    buf = cbor2.dumps('GetRandom')
    return send_nsm_req(fh, buf)

def attestation(fh: typing.TextIO, public_key: bytes = None, user_data: bytes = None, nonce: bytes = None):
    buf = cbor2.dumps({
        'Attestation': {
            'user_data': user_data,
            'nonce': nonce,
            'public_key': public_key
        }
    })
    return send_nsm_req(fh, buf)

class TestInitialNSMState(unittest.TestCase):

    def setUp(self):
        self.fh = open('/dev/nsm', 'r')

    def tearDown(self):
        self.fh.close()

    def test_001_describe_nsm_initial_state(self):
        rsp = describe_nsm(self.fh)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['DescribeNSM'])

        obj = rsp.get('DescribeNSM')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(set(obj.keys()), set(['digest', 'max_pcrs', 'module_id', 'locked_pcrs', 'version_major', 'version_minor', 'version_patch']))
        self.assertEqual(obj.get('digest'), 'SHA384')
        self.assertEqual(obj.get('max_pcrs'), 32)
        # First 16 PCRs are reserved for nitro enclave and locked from boot
        self.assertEqual(obj.get('locked_pcrs'), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.assertEqual(obj.get('version_major'), 1)
        self.assertEqual(obj.get('version_minor'), 0)
        self.assertEqual(obj.get('version_patch'), 0)

    def test_002_pcrs_initial_state(self):
        # First 16 PCRs are reserved for nitro enclave and some PCRs contain various
        # measurements. But Others from [16, 31] are not locked and start with zero.
        for i in range(0, 32):
            rsp = describe_pcr(self.fh, i)
            self.assertTrue(isinstance(rsp, dict))
            self.assertEqual(list(rsp.keys()), ['DescribePCR'])

            obj = rsp.get('DescribePCR')
            self.assertTrue(isinstance(obj, dict))
            self.assertEqual(set(obj.keys()), set(['data', 'lock']))
            if i < 16:
                self.assertTrue(obj.get('lock'))
            else:
                self.assertFalse(obj.get('lock'))
                self.assertEqual(obj.get('data'), bytes(48))

class TestVariousErrorResponse(unittest.TestCase):

    def setUp(self):
        self.fh = open('/dev/nsm', 'r')

    def tearDown(self):
        self.fh.close()

    def test_001_invalid_command(self):
        # Unknown command but valid CBOR
        buf = cbor2.dumps('UnknownCommand')
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # Invalid CBOR
        buf = b'\xFF\xFF\xFF\xFF'
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

    def test_002_invalid_property_in_valid_command(self):
        buf = cbor2.dumps({
            'DescribePCR': {
                'inde': 2
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        buf = cbor2.dumps({
            'LockPCR': {
                'inde': 2
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        buf = cbor2.dumps({
            'LockPCRs': {
                'rang': 2
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        buf = cbor2.dumps({
            'ExtendPCR': {
                'inde': 2,
                'dat': bytes([])
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

    def test_003_more_than_one_property_top_level(self):
        # 'DescribePCR' Unknown properties before and after valid property
        buf = cbor2.dumps({
            'Unknown1': 'hello',
            'DescribePCR': {
                'index': 2
            },
            'Unknown2': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'DescribePCR' Unknown property after valid property
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': 2
            },
            'Unknown': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'LockPCR' Unknown properties before and after valid property
        buf = cbor2.dumps({
            'Unknown1': 'hello',
            'LockPCR': {
                'index': 2
            },
            'Unknown2': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'LockPCR' Unknown property after valid property
        buf = cbor2.dumps({
            'LockPCR': {
                'index': 2
            },
            'Unknown': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'LockPCRs' Unknown properties before and after valid property
        buf = cbor2.dumps({
            'Unknown1': 'hello',
            'LockPCRs': {
                'range': 2
            },
            'Unknown2': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'LockPCRs' Unknown property after valid property
        buf = cbor2.dumps({
            'DescribePCR': {
                'range': 2
            },
            'Unknown': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'ExtendPCR' Unknown properties before and after valid property
        buf = cbor2.dumps({
            'Unknown1': 'hello',
            'ExtendPCR': {
                'index': 20,
                'data': bytes([1, 2, 3, 4, 5])
            },
            'Unknown2': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # 'ExtendPCR' Unknown property after valid property
        buf = cbor2.dumps({
            'ExtendPCR': {
                'index': 20,
                'data': bytes([1, 2, 3, 4, 5])
            },
            'Unknown': 'world'
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

    def test_004_describe_pcr_error_responses(self):
        # index property is string
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': ''
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is null
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': None
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is byte string
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': bytes([])
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is multi-byte integer
        # triggers 'InvalidOperation' error response
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': 4294967296
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is negative integer
        # triggers 'InvalidOperation' error response
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': -1
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is single byte but outside index
        # triggers 'InvalidIndex' error response
        buf = cbor2.dumps({
            'DescribePCR': {
                'index': 50
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidIndex')

    def test_005_lock_pcr_error_responses(self):
        # index property is string
        buf = cbor2.dumps({
            'LockPCR': {
                'index': ''
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is null
        buf = cbor2.dumps({
            'LockPCR': {
                'index': None
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is byte string
        buf = cbor2.dumps({
            'LockPCR': {
                'index': bytes([])
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is multi-byte integer
        # triggers 'InvalidOperation' error response
        buf = cbor2.dumps({
            'LockPCR': {
                'index': 4294967296
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is negative integer
        # triggers 'InvalidOperation' error response
        buf = cbor2.dumps({
            'LockPCR': {
                'index': -1
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # index property is single byte but outside index
        # triggers 'InvalidIndex' error response
        buf = cbor2.dumps({
            'LockPCR': {
                'index': 50
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidIndex')

        # Try lock already locked PCR
        rsp = lock_pcr(self.fh, 0)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'ReadOnlyIndex')

    def test_006_lock_pcrs_error_responses(self):
        # range property is string
        buf = cbor2.dumps({
            'LockPCRs': {
                'range': ''
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # range property is null
        buf = cbor2.dumps({
            'LockPCRs': {
                'range': None
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # range property is byte string
        buf = cbor2.dumps({
            'LockPCRs': {
                'range': bytes([])
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # range property is multi-byte integer
        # triggers 'InvalidOperation' error response
        buf = cbor2.dumps({
            'LockPCRs': {
                'range': 4294967296
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # range property is negative integer
        # triggers 'InvalidOperation' error response
        buf = cbor2.dumps({
            'LockPCRs': {
                'range': -1
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # range property is single byte but outside index
        # triggers 'InvalidIndex' error response
        buf = cbor2.dumps({
            'LockPCRs': {
                'range': 50
            },
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidIndex')

    def test_007_extend_pcr_error_responses(self):
        # Try extend locked PCR
        rsp = extend_pcr(self.fh, 0, bytes([0, 1, 2, 3]))
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'ReadOnlyIndex')

        # ExtendPCR without data property
        buf = cbor2.dumps({
            'ExtendPCR': {
                'index': 16,
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # ExtendPCR with data null
        buf = cbor2.dumps({
            'ExtendPCR': {
                'index': 16,
                'data': None
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

    def test_008_attestation_error_responses(self):
        # No map
        buf = cbor2.dumps({
            'Attestation': 'hello'
        })

        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

        # Invalid property type
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': 'public_key',
                'nonce': 52, # invalid type
                'user_data': 'user_data'
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'InvalidOperation')

class TestNSMOperations(unittest.TestCase):

    def setUp(self):
        self.fh = open('/dev/nsm', 'r')

    def tearDown(self):
        self.fh.close()

    def test_001_get_random(self):
        rsp = get_random(self.fh)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['GetRandom'])

        obj = rsp.get('GetRandom')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['random'])
        self.assertTrue(isinstance(obj.get('random'), bytes))

    def test_002_describe_pcr(self):
        rsp1 = describe_pcr(self.fh, 4)
        self.assertTrue(isinstance(rsp1, dict))
        self.assertEqual(list(rsp1.keys()), ['DescribePCR'])

        obj1 = rsp1.get('DescribePCR')
        self.assertTrue(isinstance(obj1, dict))
        self.assertEqual(set(obj1.keys()), set(['data', 'lock']))

        # Now try with more properties inside the map which should succeed too
        buf = cbor2.dumps({
            'DescribePCR': {
                'Unknown1': 'hello',
                'index': 4,
                'Unknown2': 'world',
            },
        })
        rsp2 = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp2, dict))
        self.assertEqual(list(rsp2.keys()), ['DescribePCR'])

        obj2 = rsp2.get('DescribePCR')
        self.assertTrue(isinstance(obj2, dict))
        self.assertEqual(set(obj2.keys()), set(['data', 'lock']))

        # Verify that the old value is still there
        self.assertEqual(obj1.get('data'), obj2.get('data'))

    def test_003_extend_pcr(self):
        # Verify extending a PCR that starts as zero works as expected
        buf = bytes([11, 0, 55, 72, 99, 255, 92, 101])
        rsp = extend_pcr(self.fh, 16, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['ExtendPCR'])
        obj = rsp.get('ExtendPCR')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['data'])
        self.assertEqual(obj.get('data').hex(), 'b33da05a0fdb71627c8c68fc4232281fc440edd6f0ac7467fa497bbb907db32d957b5fd393845fa02c264ad5ea233888')

        # extend again with some extra properties which should succeed too
        buf = cbor2.dumps({
            'ExtendPCR': {
                'extra': 'yoo',
                'data': bytes([101, 102, 255, 0, 23, 44, 77]),
                'index': 16,
                'anotherOne': 'yoho'
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['ExtendPCR'])
        obj = rsp.get('ExtendPCR')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['data'])
        self.assertEqual(obj.get('data').hex(), '022db9572e340c6fe4ae1ea55fc665226932209b42dd8c42556000e913aea3ffec9e55c2cfa7efcc5dc52b0ebf03eb5b')

        # extend PCR with zero len data
        rsp = extend_pcr(self.fh, 17, bytes([]))
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['ExtendPCR'])
        obj = rsp.get('ExtendPCR')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['data'])
        self.assertEqual(obj.get('data').hex(), '8f0d145c0368ad6b70be22e41c400eea91b971d96ba220fec9fae25a58dffdaaf72dbe8f6783d55128c9df4efaf6f8a7')

        # extend again
        rsp = extend_pcr(self.fh, 17, bytes(513))
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['ExtendPCR'])
        obj = rsp.get('ExtendPCR')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['data'])
        self.assertEqual(obj.get('data').hex(), '881f42f6a310bb0d4f37d9d75b038a9010d052f0f01a1aac8a34b38f573ba5e4dd8f3d5c8fd14e2f641774d1c4b4c96e')

        # extend again with a big data
        rsp = extend_pcr(self.fh, 17, bytes(4000))
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['ExtendPCR'])
        obj = rsp.get('ExtendPCR')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['data'])
        self.assertEqual(obj.get('data').hex(), 'ffbb97ea3c03451254d8059cbec835359939342226cb7b672a4fba3f90c3bd343bcbd3a1ab06988ce9cd139ef1709e8e')

        # extend again with string data
        buf = cbor2.dumps({
            'ExtendPCR': {
                'index': 17,
                'data': 'hello world',
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['ExtendPCR'])
        obj = rsp.get('ExtendPCR')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['data'])
        self.assertEqual(obj.get('data').hex(), 'f79d5c4d198d4d050ae118f0dbb9f24df932300db1c5c85ed85ddf3eacc2dc98585f0e38c17755defb6dfe130f1a126d')

    def test_004_lock_pcr(self):
        rsp = lock_pcr(self.fh, 16)
        self.assertEqual(rsp, 'LockPCR')

        # Try locking again
        rsp = lock_pcr(self.fh, 16)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Error'])
        self.assertEqual(rsp.get('Error'), 'ReadOnlyIndex')

        # lock with some extra properteis which should succeed too
        buf = cbor2.dumps({
            'LockPCR': {
                'Unknown1': 'hello',
                'index': 17,
                'Unknown2': 'world'
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertEqual(rsp, 'LockPCR')

    def test_005_lock_pcrs(self):
        rsp = lock_pcrs(self.fh, 20)
        self.assertEqual(rsp, 'LockPCRs')

        # lock again with the same range and some extra properties which should succeed too
        buf = cbor2.dumps({
            'LockPCRs': {
                'Unknown1': 'hello',
                'range': 20,
                'Unknown2': 'world',
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.assertEqual(rsp, 'LockPCRs')

        # verify that from [0, range - 1] are locked and others are unlocked
        for i in range(0, 32):
            rsp = describe_pcr(self.fh, i)
            self.assertTrue(isinstance(rsp, dict))
            self.assertEqual(list(rsp.keys()), ['DescribePCR'])

            obj = rsp.get('DescribePCR')
            self.assertTrue(isinstance(obj, dict))
            self.assertEqual(set(obj.keys()), set(['data', 'lock']))
            if i < 20:
                self.assertTrue(obj.get('lock'))
            else:
                self.assertFalse(obj.get('lock'))

    def test_006_describe_nsm(self):
        rsp = describe_nsm(self.fh)
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['DescribeNSM'])

        obj = rsp.get('DescribeNSM')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(set(obj.keys()), set(['digest', 'max_pcrs', 'module_id', 'locked_pcrs', 'version_major', 'version_minor', 'version_patch']))
        self.assertEqual(obj.get('digest'), 'SHA384')
        self.assertEqual(obj.get('max_pcrs'), 32)
        # In the previous operation PCRs [0, 19] have been locked
        self.assertEqual(obj.get('locked_pcrs'), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
        self.assertEqual(obj.get('version_major'), 1)
        self.assertEqual(obj.get('version_minor'), 0)
        self.assertEqual(obj.get('version_patch'), 0)

    def verify_attestation_response(self, rsp, public_key, user_data, nonce):
        self.assertTrue(isinstance(rsp, dict))
        self.assertEqual(list(rsp.keys()), ['Attestation'])

        obj = rsp.get('Attestation')
        self.assertTrue(isinstance(obj, dict))
        self.assertEqual(list(obj.keys()), ['document'])

        doc = cbor2.loads(obj.get('document'))
        self.assertTrue(isinstance(doc, list))
        self.assertEqual(len(doc), 4)

        self.assertTrue(isinstance(doc[0], bytes))
        doc0 = cbor2.loads(doc[0])
        self.assertTrue(isinstance(doc0, dict))
        self.assertEqual(list(doc0.keys()), [1])

        self.assertTrue(isinstance(doc[1], dict))
        self.assertEqual(list(doc[1].keys()), [])

        self.assertTrue(isinstance(doc[2], bytes))
        payload = cbor2.loads(doc[2])
        self.assertTrue(isinstance(payload, dict))
        self.assertEqual(set(payload.keys()), set(['module_id', 'digest', 'timestamp', 'pcrs', 'certificate', 'cabundle', 'public_key', 'user_data', 'nonce']))
        self.assertEqual(payload.get('digest'), 'SHA384')
        self.assertTrue(isinstance(payload.get('pcrs'), dict))
        pcrs = payload.get('pcrs')
        self.assertEqual(set(pcrs.keys()), set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]))
        self.assertEqual(pcrs.get(16).hex(), '022db9572e340c6fe4ae1ea55fc665226932209b42dd8c42556000e913aea3ffec9e55c2cfa7efcc5dc52b0ebf03eb5b')
        self.assertEqual(pcrs.get(17).hex(), 'f79d5c4d198d4d050ae118f0dbb9f24df932300db1c5c85ed85ddf3eacc2dc98585f0e38c17755defb6dfe130f1a126d')
        self.assertEqual(pcrs.get(18), bytes(48))
        self.assertEqual(pcrs.get(19), bytes(48))
        self.assertEqual(payload.get('public_key'), public_key)
        self.assertEqual(payload.get('user_data'), user_data)
        self.assertEqual(payload.get('nonce'), nonce)

        self.assertTrue(isinstance(doc[3], bytes))

    def test_007_attestation(self):
        # No public_key, user_data, nonce property but with extra properties
        buf = cbor2.dumps({
            'Attestation': {
                'Unknown1': 'hello',
                'Unknown2': 'world'
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, None, None)

        # public_key null, no user_data, nonce property
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': None
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, None, None)

        # public_key null, user_data null, no nonce property
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': None,
                'user_data': None
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, None, None)

        # public_key null, user_data null, nonce null
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': None,
                'user_data': None,
                'nonce': None
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, None, None)

        # public_key, user_data, nonce zero len
        buf = cbor2.dumps({
            'Attestation': {
                'nonce': bytes([]),
                'user_data': bytes([]),
                'public_key': bytes([])
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, bytes([]), bytes([]), bytes([]))

        # with public_key, user_data null, nonce null
        pk = bytes([11, 22, 0, 1, 5, 8, 9])
        buf = cbor2.dumps({
            'Attestation': {
                'nonce': None,
                'user_data': None,
                'public_key': pk
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, pk, None, None)

        # public_key null, with user_data, nonce null
        ud = bytes([22, 33, 0, 10, 55, 80, 89])
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': None,
                'nonce': None,
                'user_data': ud
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, ud, None)

        # public_key null, user_data null, with nonce
        n = bytes([44, 13, 10, 0, 5, 8, 9])
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': None,
                'nonce': n,
                'user_data': None
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, None, n)

        # with public_key, with user_data, with nonce
        pk = bytes([2, 3, 10, 88, 45, 32])
        ud = bytes([22, 13, 1, 8, 54, 23])
        n = bytes([0, 1, 2, 3, 4, 5, 8])
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': pk,
                'user_data': ud,
                'nonce': n
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, pk, ud, n)

        # big public_key, no user_data, nonce property
        pk = bytes(4050)
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': pk,
                'user_data': None,
                'nonce': None
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, pk, None, None)

        # no public_key, user_data property, big nonce
        n = bytes(4073)
        buf = cbor2.dumps({
            'Attestation': {
                'nonce': n
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        self.verify_attestation_response(rsp, None, None, n)

        # properties are string, instead of byte string
        pk = 'hello'
        ud = 'world'
        n = 'something'
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': pk,
                'user_data': ud,
                'nonce': n
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        # response always has byte string
        self.verify_attestation_response(rsp, pk.encode(), ud.encode(), n.encode())

        # string and byte string mix
        pk = bytes([1, 55, 30, 20, 34])
        ud = 'world'
        n = 'something'
        buf = cbor2.dumps({
            'Attestation': {
                'public_key': pk,
                'user_data': ud,
                'nonce': n
            }
        })
        rsp = send_nsm_req(self.fh, buf)
        # response always has byte string
        self.verify_attestation_response(rsp, pk, ud.encode(), n.encode())

def print_all_pcrs():
    fh = open('/dev/nsm', 'r')
    print("All PCR Info:")

    for i in range(32):
        print("\t", end="")
        rsp = describe_pcr(fh, i)
        if not isinstance(rsp, dict):
            print(f"PCR {i:02} unknown response. Expected dict.")
            continue
        if 'Error' in rsp:
            print(f"PCR {i:02} error response: {rsp.get('Error')}")
            continue
        obj = rsp.get('DescribePCR')
        print(f"PCR {i:02} value = {obj.get('data').hex()} , locked = {obj.get('lock')}")

    fh.close()
    return

if __name__ == '__main__':

    # Sleep for 60 seconds so that we have time to attach console to the nitro enclave VM when running in AWS
    time.sleep(60)

    # Let's print all PCRs at the beginning for manually seeing measurements
    print_all_pcrs()

    # Run the tests sequentially as some tests depend on state set by previous test methods
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTests(loader.loadTestsFromTestCase(TestInitialNSMState))
    suite.addTests(loader.loadTestsFromTestCase(TestVariousErrorResponse))
    suite.addTests(loader.loadTestsFromTestCase(TestNSMOperations))
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
