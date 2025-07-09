import unittest
from unittest.mock import patch, MagicMock
from categories.recon.methods_recon.dns_resolve.resolve_lookup import Lookup

class TestLookup(unittest.TestCase):

    @patch('dns.resolver.resolve')
    def test_forward_lookup_success(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(address='1.2.3.4')]
        result = Lookup.forward_lookup('example.com')
        self.assertEqual(result, ['1.2.3.4'])

    @patch('dns.resolver.resolve', side_effect=Exception)
    def test_forward_lookup_failure(self, _):
        result = Lookup.forward_lookup('example.com')
        self.assertEqual(result, [])

    @patch('dns.resolver.resolve')
    def test_get_cname_success(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(to_text=lambda: 'alias.example.com.')]
        result = Lookup.get_cname('www.example.com')
        self.assertEqual(result, 'alias.example.com.')

    @patch('dns.resolver.resolve', side_effect=Exception)
    def test_get_cname_failure(self, _):
        result = Lookup.get_cname('www.example.com')
        self.assertIsNone(result)

    @patch('socket.gethostbyaddr')
    def test_reverse_lookup_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ('example.com', [], [])
        result = Lookup.reverse_lookup('8.8.8.8')
        self.assertEqual(result, 'example.com')

    @patch('socket.gethostbyaddr', side_effect=Exception)
    def test_reverse_lookup_failure(self, _):
        result = Lookup.reverse_lookup('8.8.8.8')
        self.assertIsNone(result)
        
        
if __name__ == '__main__':
    unittest.main()