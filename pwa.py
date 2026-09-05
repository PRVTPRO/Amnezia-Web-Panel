"""PWA web app manifest builder.

Pure functions only — kept free of app.py imports so unit tests can exercise
manifest shape without loading the full FastAPI application.
"""


def build_manifest(site_settings, lang):
    """Return a Web App Manifest dict for the given appearance settings and language.

    ``site_settings`` is typically ``data['settings']['appearance']`` (title,
    subtitle, logo). Defaults match the appearance seed in ``load_data()``.
    """
    settings = site_settings or {}
    title = (settings.get('title') or 'Amnezia').strip() or 'Amnezia'
    subtitle = (settings.get('subtitle') or 'Web Panel').strip() or 'Web Panel'
    name = f'{title} {subtitle}'.strip()

    return {
        'name': name,
        'short_name': title,
        'description': name,
        'start_url': '/',
        'scope': '/',
        'display': 'standalone',
        'background_color': '#0a0a0f',
        'theme_color': '#0a0a0f',
        'dir': 'rtl' if lang == 'fa' else 'ltr',
        'lang': lang or 'en',
        'icons': [
            {
                'src': '/static/icons/icon-192.png',
                'sizes': '192x192',
                'type': 'image/png',
                'purpose': 'any',
            },
            {
                'src': '/static/icons/icon-512.png',
                'sizes': '512x512',
                'type': 'image/png',
                'purpose': 'any',
            },
            {
                'src': '/static/icons/maskable-192.png',
                'sizes': '192x192',
                'type': 'image/png',
                'purpose': 'maskable',
            },
            {
                'src': '/static/icons/maskable-512.png',
                'sizes': '512x512',
                'type': 'image/png',
                'purpose': 'maskable',
            },
        ],
        'shortcuts': [
            {
                'name': 'Connections',
                'short_name': 'Connections',
                'url': '/my',
                'icons': [{'src': '/static/icons/icon-192.png', 'sizes': '192x192'}],
            },
            {
                'name': 'Users',
                'short_name': 'Users',
                'url': '/users',
                'icons': [{'src': '/static/icons/icon-192.png', 'sizes': '192x192'}],
            },
        ],
    }
