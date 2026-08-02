#!/usr/bin/env python3

import unittest

from firstboot_flow import rng_raw_first_boot
from firstboot_reference import (
    build_vector,
    fixed_skip_raw,
    simulate_firstboot,
    standard_setup_post_terms_sessions,
)


class FirstBootReferenceTests(unittest.TestCase):
    def test_independent_flow_reference_matches(self):
        vectors = (
            (0, 0, 0),
            (1, 2, 18),
            (0xD36D2096, 2, 22),
            (0xFFFFFFFF, 3, 34),
        )
        for pad, pre_terms_sessions, post_terms_sessions in vectors:
            with self.subTest(
                pad=pad,
                pre_terms_sessions=pre_terms_sessions,
                post_terms_sessions=post_terms_sessions,
            ):
                primary = simulate_firstboot(
                    pad,
                    pre_terms_sessions=pre_terms_sessions,
                    post_terms_sessions=post_terms_sessions,
                )
                independent = rng_raw_first_boot(
                    pad,
                    0,
                    0,
                    pre_terms_sessions,
                    post_terms_sessions,
                )
                if independent is None:
                    self.fail("independent reference hit continuous-test failure")
                self.assertEqual(primary.raw.hex(), independent["raw_hex"])
                self.assertEqual(primary.entropy.hex(), independent["entropy_hex"])
                self.assertEqual(primary.chip_skip, independent["chip_skip"])
                self.assertEqual(primary.mixer_skip, independent["mixer_skip"])

    def test_standard_setup_has_nine_even_post_terms_session_counts(self):
        self.assertEqual(
            [standard_setup_post_terms_sessions(digits) for digits in range(4, 13)],
            list(range(18, 35, 2)),
        )
        with self.assertRaises(ValueError):
            standard_setup_post_terms_sessions(3)
        with self.assertRaises(ValueError):
            standard_setup_post_terms_sessions(13)

    def test_flow_draw_counts_replay_exact_final_rng_state(self):
        pad = 0xD36D2096
        pre_terms_sessions = 2
        post_terms_sessions = 17

        flow = simulate_firstboot(
            pad,
            pre_terms_sessions=pre_terms_sessions,
            post_terms_sessions=post_terms_sessions,
        )

        self.assertEqual(
            flow.chip_skip,
            3134 + 3 * (pre_terms_sessions + post_terms_sessions),
        )
        self.assertGreater(flow.mixer_skip, flow.chip_skip)
        self.assertEqual(
            flow.raw,
            fixed_skip_raw(pad, flow.chip_skip, flow.mixer_skip),
        )

    def test_one_additional_keypad_session_changes_the_seed_candidate(self):
        common = {"pad": 0xD36D2096, "pre_terms_sessions": 2}
        before = simulate_firstboot(**common, post_terms_sessions=17)
        after = simulate_firstboot(**common, post_terms_sessions=18)

        self.assertEqual(after.chip_skip - before.chip_skip, 3)
        self.assertNotEqual(after.raw, before.raw)
        self.assertNotEqual(after.entropy, before.entropy)

    def test_vector_contains_a_self_consistent_bip84_target(self):
        vector = build_vector(
            pad=0xD36D2096,
            pre_terms_sessions=2,
            post_terms_sessions=17,
            address_index=0,
        )

        self.assertEqual(vector["chip_skip"], 3191)
        self.assertEqual(len(bytes.fromhex(vector["raw"])), 32)
        self.assertEqual(len(bytes.fromhex(vector["entropy"])), 32)
        self.assertEqual(len(bytes.fromhex(vector["priv"])), 32)
        self.assertEqual(len(bytes.fromhex(vector["h160"])), 20)
        self.assertTrue(vector["address"].startswith("bc1q"))


if __name__ == "__main__":
    unittest.main()
