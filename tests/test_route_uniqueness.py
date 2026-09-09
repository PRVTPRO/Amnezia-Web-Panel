"""No two handlers may claim the same path and method.

Starlette matches routes in definition order, so a second registration of the
same (path, method) is dead code that the OpenAPI schema still advertises. A
merge produced exactly that for POST /api/servers/{id}/protocol/rename: the
copy with the length cap never ran.
"""

import collections
import unittest

import app as panel


class RouteUniquenessTests(unittest.TestCase):
    def test_every_path_and_method_is_registered_once(self):
        seen = collections.Counter()
        for route in panel.app.routes:
            for method in getattr(route, 'methods', None) or []:
                seen[(getattr(route, 'path', ''), method)] += 1
        duplicates = sorted(key for key, count in seen.items() if count > 1)
        self.assertEqual(duplicates, [], f"duplicate route registrations: {duplicates}")


if __name__ == '__main__':
    unittest.main()
