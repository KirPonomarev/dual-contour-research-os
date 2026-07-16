.PHONY: contracts test

contracts:
	python3 tools/validate_contracts.py

test: contracts
	python3 -m unittest discover -s tests -p 'test_*.py'
