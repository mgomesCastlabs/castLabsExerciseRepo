
MKFILE      = Makefile
GMAKE       = ${MAKE} --no-print-directory
UNAME      ?= ${shell uname -s}


NAME_PREFIX = python_programming_task_
PROXY_NAME = ${NAME_PREFIX}proxy_1


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
	docker-compose build

up :
	docker-compose up -d

stop :
	docker-compose stop

restart :
	docker-compose restart

test :
	echo "\n"
	docker exec -it ${PROXY_NAME} python tester.py

status :
	echo "\n"
	curl 'http://localhost:8080/status'

all :	build up wait test wait status 
