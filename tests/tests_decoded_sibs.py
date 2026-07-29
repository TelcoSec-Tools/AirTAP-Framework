#!/usr/bin/python3
import unittest
from src.modules.decoded_sibs_dump import SIB, SIB_NAME_TO_CLASS

class DecodedSibsTests(unittest.TestCase):

    def test_sib_segment_assembly_out_of_order(self):
        sib = SIB()
        error_logs = []

        def on_error(msg):
            error_logs.append(msg)

        # Attempt out-of-order segment insertion (expected index 0, passed 1)
        res = sib.add_segment_and_decode(
            radio_bearer=1,
            sfn_prime=10,
            sib_type='masterInformationBlock',
            segment_index=1,
            is_final=False,
            segment_data_int=0x1234,
            segment_data_bitlen=16,
            on_sib_decoding_error=on_error
        )

        self.assertIsNone(res)
        self.assertEqual(len(error_logs), 1)
        self.assertIn('Uncomplete', error_logs[0])

    def test_sib_unknown_type_handling(self):
        sib = SIB()
        error_logs = []

        def on_error(msg):
            error_logs.append(msg)

        res = sib.add_segment_and_decode(
            radio_bearer=1,
            sfn_prime=10,
            sib_type='unknownCustomSibType',
            segment_index=0,
            is_final=True,
            segment_data_int=0x1234,
            segment_data_bitlen=16,
            on_sib_decoding_error=on_error
        )

        self.assertIsNone(res)
        self.assertEqual(len(error_logs), 1)
        self.assertIn('Unknown or unhandled SIB type', error_logs[0])

if __name__ == '__main__':
    unittest.main()
