import dcos_installer.backend
from aiohttp import web


def hash_password(request):
    if request.method != 'POST':
        return web.json_response({"status": "error", "message": "Only POST is supported"}, status=400)

    post_data = yield from request.json()

    if 'password' not in post_data:
        return web.json_response(
            {
                "status": "error",
                "message": "`password` must be set in POST"},
            status=400)

    hashed_password = dcos_installer.backend.hash_password(post_data['password'])
    return web.json_response({'hashed_password': hashed_password})


def extend_app(app):
    app.router.add_route('POST', '/api/v1/hash_password', hash_password)
