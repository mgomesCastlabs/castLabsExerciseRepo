import aiohttp
import asyncio
from datetime import datetime


TARGET_TEST_URL="http://127.0.0.1:8080"
failedRequestsCount=0
successfullRequestsCount=0
headers={"Authorization": "Basic bG9naW46cGFzcw=="}
tester_payload={"message":"fire in the hole!"}
NUMBER_OF_REQUESTS=1000

timeout = aiohttp.ClientTimeout(total=10) # 10 seconds client timeout

async def post(url, payload, session):
	try:
		async with session.post(
			url, headers=headers,
			data=payload, 
			ssl = False, 
			timeout = aiohttp.ClientTimeout(
				total=None, 
				sock_connect = 10, 
				sock_read = 10
			)
		) as response:
			content = await response.read()
			return (url, 'OK', content)
	except Exception as e:
		print(e)
		return (url, 'ERROR', str(e))

async def testerMain():
	tasks = []
	async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
		for i in range(NUMBER_OF_REQUESTS):
			task = asyncio.ensure_future(post(TARGET_TEST_URL, tester_payload, session))
			tasks.append(task)
		responses = asyncio.gather(*tasks)
		await responses
	return responses

if __name__ == "__main__":
	print("initiating test run, stand by...")
	successfulRequestsCount=0

	startTime=datetime.utcnow()

	loop = asyncio.get_event_loop()
	asyncio.set_event_loop(loop)
	task = asyncio.ensure_future(testerMain())
	loop.run_until_complete(task)
	endTime=datetime.utcnow()
	result = task.result().result()
	
	for individualResult in result:
		if 'OK' in individualResult[1]:
			successfulRequestsCount+=1

	print("\nTest run complete:\nTotal number of individual post requests: "+str(NUMBER_OF_REQUESTS)+"\nNumber of successful requests: "+str(successfulRequestsCount)+ "\nTotal test elapsed time: "+str(endTime-startTime))


