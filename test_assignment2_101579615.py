"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest
from assignment2_101579615 import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):

        # Create a PortScanner with target 127.0.0.1
        scanner = PortScanner("127.0.0.1")

        # Assert scanner.target equals 127.0.0.1
        self.assertEqual(scanner.target, "127.0.0.1")

        # Assert scanner.scan_results is an empty list
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        # Create a PortScanner object
        scanner = PortScanner("127.0.0.1")

        # Manually add these tuples to scanner.scan_results
        scanner.scan_results.append((22, "Open", "SSH"))
        scanner.scan_results.append((23, "Closed", "Telnet"))
        scanner.scan_results.append((80, "Open", "HTTP"))

        # Call get_open_ports() and assert the returned list has exactly 2 items
        open_ports = scanner.get_open_ports()
        self.assertEqual(len(open_ports), 2)

        # Additional assertions to verify the correct ports are returned
        self.assertIn((22, "Open", "SSH"), open_ports)
        self.assertIn((80, "Open", "HTTP"), open_ports)

    def test_common_ports_dict(self):
        # Assert common_ports[80] equals HTTP
        self.assertEqual(common_ports[80], "HTTP")

        # Assert common_ports[22] equals SSH
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
         # Create a PortScanner with target 127.0.0.1
        scanner = PortScanner("127.0.0.1")

        # Try setting scanner.target to empty string
        scanner.target = ""

        # Assert scanner.target is still 127.0.0.1 and the setter should reject empty string
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
