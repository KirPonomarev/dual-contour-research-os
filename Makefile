.PHONY: contracts test

contracts:
	python3 tools/validate_contracts.py
	python3 tools/verify_freeze_receipt.py
	python3 tools/validate_a1_contracts.py
	python3 tools/verify_a1_freeze_receipt.py
	python3 tools/verify_r04e_provider_proof.py

test: contracts
	python3 -m unittest discover -s tests -p 'test_*.py'
	@if [ -d tests/stage0b ]; then python3 -m unittest discover -s tests/stage0b -p 'test_*.py'; fi
