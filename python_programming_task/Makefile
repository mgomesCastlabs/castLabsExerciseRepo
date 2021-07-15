
MKFILE      = Makefile
GMAKE       = ${MAKE} --no-print-directory
UNAME      ?= ${shell uname -s}


NAME_PREFIX = python_programming_task_
PROXY_NAME = ${NAME_PREFIX}proxy_1
HTTP_PORT = 8080

down :
	docker-compose down
	docker ps | tail -n +2 | awk '/${NAME_PREFIX}/ {print $$1}' | xargs docker kill

clean : down
	- docker images | tail -n +2 | awk '/${NAME_PREFIX}/ {print $$3}' | xargs docker rmi
	find . -type f -name "*.tmp" -exec rm {} + ;

hardclean : clean
	docker ps | tail -n +2 | awk '/${NAME_PREFIX}/ {print $$1}' | xargs docker kill -f
	docker images | tail -n +2 | awk '/${NAME_PREFIX}/ {print $$3}' | xargs docker rmi -f

wait :
	sleep 1

build : down clean
	-mv docker-compose.yml.bu docker-compose.yml
	-mv proxy/Dockerfile.bu proxy/Dockerfile
	-mv proxy/main.py.bu proxy/main.py
	-mv proxy/tester.py.bu proxy/tester.py
	sed -i.bu 's/8080/${HTTP_PORT}/g' docker-compose.yml
	sed -i.bu 's/EXPOSE 8080/EXPOSE ${HTTP_PORT}/' proxy/Dockerfile
	sed -i.bu 's/LISTEN_PORT = 8080/LISTEN_PORT = ${HTTP_PORT}/' proxy/main.py
	sed -i.bu 's/http:\/\/127.0.0.1:8080/http:\/\/127.0.0.1:${HTTP_PORT}/' proxy/tester.py
	docker-compose build

up:
	docker-compose up -d

run:	up

stop :
	docker-compose stop

restart :
	docker-compose restart

test :
	echo "\n"
	docker exec -it ${PROXY_NAME} python tester.py

status :
	echo "\n"
	curl 'http://localhost:${HTTP_PORT}/status'

all :	build up wait test wait status 
