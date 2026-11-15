# -*- coding: utf-8 -*-
"""I1 masking: per-instance generation, address pools and tag validation."""

import ipaddress
import re
import unittest

from managers.awg_junk import (
    DEFAULT_I1,
    DOMAIN_POOLS,
    DEVICE_PROFILES,
    catalog,
    generate_i1,
    is_legacy_default,
    is_valid_domain,
    parse_i1,
    profile_domains,
)
from managers.awg_manager import generate_awg_params, validate_special_junk

I1_RE = re.compile(r'^<r 2><b 0x[0-9A-F]+>$')


class GenerateI1Test(unittest.TestCase):
    def test_generated_value_is_a_dns_answer(self):
        value = generate_i1('icloud.com')
        self.assertRegex(value, I1_RE)
        parsed = parse_i1(value)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['domain'], 'icloud.com')
        self.assertTrue(parsed['in_pool'])
        self.assertFalse(parsed['default'])
        self.assertLess(parsed['size'], 1280)

    def test_address_belongs_to_the_domain_pool(self):
        for domain, pool in DOMAIN_POOLS.items():
            with self.subTest(domain=domain):
                parsed = parse_i1(generate_i1(domain))
                self.assertTrue(
                    ipaddress.ip_address(parsed['ip']) in ipaddress.ip_network(pool['cidr']),
                    f"{parsed['ip']} is outside {pool['cidr']}")

    def test_random_domain_when_none_given(self):
        seen = {parse_i1(generate_i1())['domain'] for _ in range(40)}
        self.assertTrue(seen.issubset(set(DOMAIN_POOLS)))
        self.assertGreater(len(seen), 1)

    def test_values_differ_between_calls(self):
        first = generate_i1('www.google.com')
        second = generate_i1('www.google.com')
        self.assertNotEqual(first, second)

    def test_custom_domain_uses_the_requested_pool(self):
        parsed = parse_i1(generate_i1('example.org', 'cloudflare.com'))
        self.assertEqual(parsed['domain'], 'example.org')
        self.assertTrue(ipaddress.ip_address(parsed['ip'])
                        in ipaddress.ip_network('104.16.0.0/13'))
        # The domain is not in the catalog, so no owner can be claimed.
        self.assertIsNone(parsed['owner'])

    def test_custom_domain_without_pool_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_i1('example.org')

    def test_unknown_pool_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_i1('example.org', 'not-a-pool.example')

    def test_invalid_domains_are_rejected(self):
        for domain in ('', 'localhost', 'http://example.com', 'a..b',
                       'exa mple.com', '-bad.example', 'bad-.example'):
            with self.subTest(domain=domain):
                self.assertFalse(is_valid_domain(domain))


class DefaultDetectionTest(unittest.TestCase):
    def test_public_default_is_recognised(self):
        self.assertTrue(is_legacy_default(DEFAULT_I1))
        self.assertTrue(is_legacy_default(DEFAULT_I1.upper()))
        self.assertFalse(is_legacy_default(generate_i1()))

    def test_public_default_parses_to_the_yandex_address(self):
        parsed = parse_i1(DEFAULT_I1)
        self.assertEqual(parsed['domain'], 'icloud.com')
        self.assertEqual(parsed['ip'], '77.88.55.55')
        self.assertTrue(parsed['default'])
        self.assertFalse(parsed['in_pool'])


class CatalogTest(unittest.TestCase):
    def test_catalog_and_profiles_agree(self):
        entries = {item['domain']: item for item in catalog()}
        self.assertGreaterEqual(len(entries), 8)
        for item in entries.values():
            ipaddress.ip_network(item['cidr'])
            self.assertTrue(item['owner'])
        for key, domains in DEVICE_PROFILES:
            with self.subTest(profile=key):
                self.assertTrue(domains)
                self.assertTrue(set(domains).issubset(entries))
        self.assertEqual(profile_domains('nope'), profile_domains('any'))


class TagValidationTest(unittest.TestCase):
    def test_supported_tags_are_counted(self):
        self.assertEqual(validate_special_junk('<r 2><b 0xdeadbeef>'), 6)
        self.assertEqual(validate_special_junk('<t>'), 4)
        self.assertEqual(validate_special_junk('<rc 8><rd 4>'), 12)
        self.assertEqual(validate_special_junk(' <b 0x00> '), 1)

    def test_kernel_only_tag_is_rejected(self):
        with self.assertRaisesRegex(ValueError, '<c>'):
            validate_special_junk('<c>')

    def test_go_only_tags_are_rejected(self):
        for tag in ('<d>', '<ds 2>', '<dz 4>'):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    validate_special_junk(tag)

    def test_unknown_tag_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_special_junk('<x 4>')

    def test_oversized_packet_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_special_junk('<r 1281>')


class GeneratorWiringTest(unittest.TestCase):
    def test_every_non_legacy_protocol_gets_its_own_i1(self):
        cases = {
            'awg': generate_awg_params(use_ranges=True),
            'awg2': generate_awg_params(use_ranges=True),
            'awg3': generate_awg_params(awg3=True),
        }
        for name, params in cases.items():
            with self.subTest(protocol=name):
                self.assertIn('i1', params)
                parsed = parse_i1(params['i1'])
                self.assertIsNotNone(parsed)
                self.assertFalse(parsed['default'])

    def test_legacy_has_no_special_junk(self):
        self.assertNotIn('i1', generate_awg_params())

    def test_requested_domain_is_used(self):
        params = generate_awg_params(awg3=True, i1_domain='github.com')
        self.assertEqual(parse_i1(params['i1'])['domain'], 'github.com')

    def test_custom_domain_needs_pool(self):
        with self.assertRaises(ValueError):
            generate_awg_params(awg3=True, i1_domain='example.org')
        params = generate_awg_params(awg3=True, i1_domain='example.org',
                                     i1_pool='github.com')
        self.assertEqual(parse_i1(params['i1'])['domain'], 'example.org')


class UpdateOnlyI1Test(unittest.TestCase):
    """Regenerating I1 must not silently drop I2-I5."""

    def _manager(self):
        from managers.awg_manager import AWGManager
        manager = AWGManager(ssh_manager=None)
        manager._base_protocol = lambda proto: 'awg3'
        manager._get_awg_params_from_config = lambda proto: {
            'i1': '<r 2><b 0x8580>', 'i2': '<t>'}
        config = '[Interface]\nI1 = <r 2><b 0x8580>\nI2 = <t>\n\n[Peer]\n'
        manager._get_server_config = lambda proto: config
        written = {}
        manager._write_server_config = lambda proto, text: written.setdefault('config', text)
        manager._sync_server_config = lambda proto: None
        manager._restart_container = lambda proto: None
        manager.get_awg_settings = lambda proto: {'status': 'ok'}
        return manager, written

    def test_replaces_i1_and_keeps_the_rest(self):
        manager, written = self._manager()
        manager.update_awg_settings('awg3', i1_value='<r 2><b 0xdeadbeef>')
        config = written['config']
        self.assertIn('I1 = <r 2><b 0xdeadbeef>', config)
        self.assertIn('I2 = <t>', config)
        self.assertNotIn('0x8580', config)

    def test_only_provided_packets_are_touched(self):
        manager, written = self._manager()
        manager.update_awg_settings('awg3', special_junk={'i1': '<r 2><b 0x01>'})
        config = written['config']
        self.assertIn('I1 = <r 2><b 0x01>', config)
        # I2 was not sent, so it stays as it was.
        self.assertIn('I2 = <t>', config)

    def test_empty_string_clears_only_that_packet(self):
        manager, written = self._manager()
        manager.update_awg_settings('awg3', special_junk={'i2': ''})
        config = written['config']
        self.assertIn('I1 = <r 2><b 0x8580>', config)
        self.assertNotIn('I2 =', config)

    def test_unchanged_value_is_not_validated(self):
        from managers.awg_manager import AWGManager
        manager = AWGManager(ssh_manager=None)
        manager._base_protocol = lambda proto: 'awg3'
        # An instance saved before <c> was rejected still has it in I1.
        manager._get_awg_params_from_config = lambda proto: {'i1': '<c>'}
        manager._get_server_config = lambda proto: '[Interface]\nI1 = <c>\n\n[Peer]\n'
        written = {}
        manager._write_server_config = lambda proto, text: written.setdefault('config', text)
        manager._sync_server_config = lambda proto: None
        manager._restart_container = lambda proto: None
        manager.get_awg_settings = lambda proto: {'status': 'ok'}

        # Saving MTU alone must not raise, and the old packet is untouched.
        manager.update_awg_settings('awg3', mtu='1300')
        self.assertIn('I1 = <c>', written['config'])
        # Sending the same value back is not "new input" either.
        manager.update_awg_settings('awg3', special_junk={'i1': '<c>'})
        self.assertIn('I1 = <c>', written['config'])


class HardeningTest(unittest.TestCase):
    """Guards added after review: no line breaks, no non-ASCII, strict <b>."""

    def test_line_breaks_in_a_packet_are_rejected(self):
        for value in ('<t>\n<r 2>', '<r 2>\r\n<b 0x00>', '<r\n2>'):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'line breaks'):
                    validate_special_junk(value)

    def test_non_ascii_domain_is_rejected(self):
        for domain in ('пример.рф', 'іcloüd.com', 'exämple.com'):
            with self.subTest(domain=domain):
                self.assertFalse(is_valid_domain(domain))

    def test_numeric_tld_is_rejected(self):
        self.assertFalse(is_valid_domain('host.123'))

    def test_hex_tag_without_prefix_is_not_parsed(self):
        self.assertIsNone(parse_i1('<r 2><b deadbeef>'))
        self.assertIsNone(parse_i1('<r 2><b>'))

    def test_non_printable_and_padded_tags_are_rejected(self):
        for value in ('<r  2>', '<r 2 >', '< r 2>', '<r\u00a02>', '<t>\x0b',
                      '<r 2>\t<b 0x00>'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_special_junk(value)

    def test_full_packet_in_a_single_tag_is_parsed(self):
        from managers.awg_junk import tags_to_bytes
        packet = '<b 0x' + tags_to_bytes(DEFAULT_I1).hex() + '>'
        parsed = parse_i1(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['domain'], 'icloud.com')
        self.assertTrue(is_legacy_default(packet))

    def test_regeneration_does_not_require_valid_old_i2(self):
        from managers.awg_manager import AWGManager
        manager = AWGManager(ssh_manager=None)
        manager._base_protocol = lambda proto: 'awg3'
        # An instance saved before <c> was rejected still carries it in I2.
        manager._get_awg_params_from_config = lambda proto: {
            'i1': '<r 2><b 0x8580>', 'i2': '<c>'}
        manager._get_server_config = lambda proto: (
            '[Interface]\nI1 = <r 2><b 0x8580>\nI2 = <c>\n\n[Peer]\n')
        written = {}
        manager._write_server_config = lambda proto, text: written.setdefault('config', text)
        manager._sync_server_config = lambda proto: None
        manager._restart_container = lambda proto: None
        manager.get_awg_settings = lambda proto: {'status': 'ok'}

        manager.update_awg_settings('awg3', i1_value='<r 2><b 0xdeadbeef>')
        config = written['config']
        self.assertIn('I1 = <r 2><b 0xdeadbeef>', config)
        self.assertIn('I2 = <c>', config)


if __name__ == '__main__':
    unittest.main()
