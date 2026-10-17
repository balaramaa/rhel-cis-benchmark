.PHONY: generate check lint syntax bundles

generate:   ## rebuild rhel8/ rhel9/ rhel10/ from tools/
	python3 tools/generate.py

check:      ## fail if generated files are stale
	python3 tools/generate.py --check

lint:
	yamllint .
	ansible-lint

syntax:
	ansible-playbook -i localhost, --syntax-check site.yml
	for v in 8 9 10; do (cd rhel$$v && ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i localhost, --syntax-check playbook.yml) || exit 1; done

bundles:    ## build the per-OS download archives into dist/
	mkdir -p dist
	for v in 8 9 10; do tar czf dist/cis-rhel$$v.tar.gz rhel$$v; done
	tar czf dist/cis-rhel-all.tar.gz apply.sh rhel8 rhel9 rhel10
	ls -lh dist
