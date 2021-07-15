import logging
import sys

import uuid
from datetime import datetime
import jwt
import json

import asyncio
import aiohttp
from aiohttp import web



TARGET_SERVER_URL = 'https://postman-echo.com/post' #since postman echo doesn't support any URI apart from /post, all incoming requests URI will default to this forwarded path
LOGGING_LEVEL = logging.DEBUG
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
JWT_ENCODING_ALGORITHM='HS512'
JWT_ENCODING_SECRET="a9ddbcaba8c0ac1a0a812dc0c2f08514b23f2db0a68343cb8199ebb38a6d91e4ebfb378e22ad39c2d01 d0b4ec9c34aa91056862ddace3fbbd6852ee60c36acbf"
#The exercise spec shows the encoding secret with a space character in the middle of the string, I suspect that this is a typo but regardless will keep it as it may be intencional

proxiedPostCount = 0

logger = logging.getLogger("runproxy")

async def issueJwt(username):
    
    iat = str(datetime.utcnow())
    jti = str(uuid.uuid4())
    payload = {"username": username, "date": datetime.utcnow().strftime("%d/%m/%Y %H:%M:%S")}
    jwtRawPayload = { "iat": iat, "jti": jti, "payload": payload}
    
    logger.debug("JWT payload to be issued:" + json.dumps(jwtRawPayload))

    return jwt.encode(jwtRawPayload, JWT_ENCODING_SECRET, algorithm=JWT_ENCODING_ALGORITHM)


async def handleStatus(request):
    
    logger.info("incoming status request")
    
    jsonStatus = {"startTimeUtc":startTime.strftime("%d/%m/%Y %H:%M:%S"),
                  "timeElapsedSinceServerLaunch":str(datetime.utcnow()-startTime),
                  "proxiedPostCount":proxiedPostCount}
    
    logger.debug("returning the following status json: " + json.dumps(jsonStatus))
    
    return web.json_response(jsonStatus)


async def handleProxy(request):
    
    global proxiedPostCount 

    data = await request.read()
    
    if len(request.query_string) > 0:
        queryParams="?"+request.query_string
    else:
        queryParams=""

    try:
        username=aiohttp.helpers.BasicAuth.decode(request.headers['authorization'])[0]
    except:
        logger.debug("issue found while decoding BasicAuth header")
        return web.Response(body="issue found while decoding BasicAuth header")
    
    requestHeaders=dict(request.headers)

    logger.info("incoming request to be proxied")

    logger.debug("Incoming request to be proxied - \nrequest.headers={}\nrequest.method={}\nrequest.body={}\n".format( request.headers, request.method, data))

    requestHeaders['x-my-jwt']= await issueJwt(username)

    async with aiohttp.ClientSession() as session:

        async with session.request(request.method, TARGET_SERVER_URL+queryParams, headers=requestHeaders,  data=data) as resp:
            res = resp
            raw = await res.read()
    logger.info("Origin reply, status code: " + str(res.status))
    logger.debug("Origin reply - \nHeader: {}\nStatus: {}\nBody: {}".format(res.headers, res.status, res.content))

    headers = dict(res.headers)
    
    if 'Transfer-Encoding' in headers:
        del headers['Transfer-Encoding']
        headers["Content-Length"] = str(len(raw))
    
    proxiedPostCount+=1
    
    return web.Response(body=raw, status=res.status, headers=headers)


if __name__ == "__main__":
    startTime=datetime.utcnow()
    logging.root.setLevel(LOGGING_LEVEL)
    logging.root.addHandler(logging.StreamHandler(sys.stdout))

    app = web.Application()
    app.add_routes([web.get('/', handleStatus),
                    web.get('/status', handleStatus),
                    web.post('/', handleProxy),
                    web.post('/{path:.*}', handleProxy)])


    loop = asyncio.get_event_loop()

    web.run_app(app, host=LISTEN_HOST, port=LISTEN_PORT)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass