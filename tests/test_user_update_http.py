"""In-process ASGI HTTP checks of extracted real handlers; no network/Panel startup."""
import asyncio
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
from test_user_update_race import actual_code, SOURCE, GIB


class ApiSmoke(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='panel174-asgi-')
        self.file = Path(self.temp.name) / 'data.json'
        self.ns = actual_code(SOURCE, self.file, Request, JSONResponse)
        self.ns['_check_admin'] = lambda r: r.headers.get('X-Synthetic-Admin') == 'yes'
        self.ns['get_current_user'] = lambda r: {
            'role': 'admin' if self.ns['_check_admin'](r) else 'user'}
        self.ns['save_data'](dict(users=[dict(id='test', username='before', enabled=False,
            traffic_used=430*GIB, traffic_limit=500*GIB, expiration_date='2030-01-01')],
            servers=[], user_connections=[]))
        self.app = FastAPI()
        self.app.post('/api/users/{user_id}/update')(self.ns['api_update_user'])
        self.app.post('/api/users/{user_id}/toggle')(self.ns['api_toggle_user'])
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
            base_url='http://synthetic.invalid', headers={'X-Synthetic-Admin': 'yes'})

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp.cleanup()

    def user(self):
        return self.ns['load_data']()['users'][0]

    async def test_username_only_http(self):
        before = self.user()
        response = await self.client.post('/api/users/test/update', json={'username': 'after'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'success'})
        self.assertEqual(self.user(), dict(before, username='after'))

    async def test_quota_update_http(self):
        response = await self.client.post('/api/users/test/update', json={'traffic_limit': 1000})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.user()['traffic_limit'], 1000*GIB)
        self.assertEqual(self.user()['traffic_used'], 430*GIB)
        self.assertTrue(self.user()['enabled'])

    async def test_explicit_zero_http(self):
        response = await self.client.post('/api/users/test/update', json={'traffic_limit': 0})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.user()['traffic_limit'], 0)
        self.assertEqual(self.user()['traffic_used'], 430*GIB)

    async def test_toggle_http(self):
        before = self.user()
        response = await self.client.post('/api/users/test/toggle', json={'enabled': True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'status': 'success', 'enabled': True})
        self.assertEqual(self.user(), dict(before, enabled=True))

    async def test_forbidden_http_unchanged(self):
        before = self.file.read_bytes()
        for action, body in [('update', {'traffic_limit': 1000}), ('toggle', {'enabled': True})]:
            response = await self.client.post('/api/users/test/'+action, json=body,
                                              headers={'X-Synthetic-Admin': 'no'})
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_missing_http_unchanged(self):
        before = self.file.read_bytes()
        for action, body in [('update', {'traffic_limit': 1000}), ('toggle', {'enabled': True})]:
            response = await self.client.post('/api/users/missing/'+action, json=body)
            self.assertEqual(response.status_code, 404)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_validation_http_unchanged(self):
        before = self.file.read_bytes()
        response = await self.client.post('/api/users/test/update',
                                          json={'traffic_limit': 'not-a-number'})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.file.read_bytes(), before)

    async def test_expiration_null_and_omission_http(self):
        response = await self.client.post('/api/users/test/update', json={'expiration_date': None})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.user()['expiration_date'])
        response = await self.client.post('/api/users/test/update', json={'description': 'test'})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.user()['expiration_date'])
        self.assertEqual(self.user()['traffic_limit'], 500*GIB)

    async def test_two_http_requests_persist_latest_fields(self):
        data = self.ns['load_data']()
        data['servers'] = [{'host': 'mock.invalid'}]
        data['user_connections'] = [dict(id='conn', user_id='test', server_id=0,
                                         protocol='awg', client_id='mock')]
        self.ns['save_data'](data)
        entered, release = asyncio.Event(), asyncio.Event()
        ssh = SimpleNamespace(connect=lambda: None, disconnect=lambda: None)
        self.ns['get_ssh'] = lambda _: ssh
        self.ns['get_protocol_manager'] = lambda *args: object()
        self.ns['_manager_call'] = lambda *args: None

        async def to_thread(function, *args):
            if function is self.ns['get_ssh']:
                entered.set()
                await release.wait()
            return function(*args)

        self.ns['asyncio'] = SimpleNamespace(to_thread=to_thread)
        first = asyncio.create_task(self.client.post('/api/users/test/update',
                                                     json={'traffic_limit': 1000}))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            response = await asyncio.wait_for(self.client.post('/api/users/test/update',
                                               json={'expiration_date': '2031-01-01'}), 2)
            self.assertEqual(response.status_code, 200)
            async with self.ns['DATA_LOCK']:
                data = self.ns['load_data']()
                data['users'][0]['traffic_used'] = 480*GIB
                self.ns['save_data'](data)
        finally:
            release.set()
            first_response = await asyncio.wait_for(first, 2)
        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(self.user()['traffic_used'], 480*GIB)
        self.assertEqual(self.user()['expiration_date'], '2031-01-01')
        self.assertEqual(self.user()['traffic_limit'], 1000*GIB)


if __name__ == '__main__':
    unittest.main(verbosity=2)
