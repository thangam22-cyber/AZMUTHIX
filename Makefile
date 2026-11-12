.PHONY: dev test build samples docker
test:
	cd backend && python -m pytest -q
	cd frontend && npm test
build:
	cd frontend && npm run build
samples:  ## regenerate synthetic evidence and copy into the UI's demo bundle
	python sample-data/generate.py && cp sample-data/auth.log sample-data/access.log sample-data/app-events.jsonl sample-data/harmless-test.txt frontend/public/samples/
docker:
	docker compose up --build
