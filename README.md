# tm-MisconfigurationDetector
Scans configuration files (e.g., YAML, JSON) against a set of predefined security best practices to identify common misconfigurations and vulnerabilities. Reports findings with severity levels. Uses `yaml` and `json` libraries for parsing and `jsonschema` for validation. - Focused on Tools for creating and visualizing threat models based on system architectures and data flows.  This includes automating the process of identifying potential attack vectors and prioritizing mitigation efforts.

The built-in predefined rules check for debug mode enabled (`debug` set to true), a plaintext `password` key present in the configuration, TLS explicitly disabled (`tls_enabled` set to false), and binding to all interfaces (`bind_address` set to `0.0.0.0`). They run when no rules file is given with `-r`.

Custom rules use `jsonschema` rules or `custom` rules. A custom condition is checked by a restricted interpreter, never run as code. Allowed shapes are comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`), boolean `and`, `or` and `not`, membership with `in` and `not in`, plain literals, the name `config`, bare names that match configuration fields, and subscripts on the config mapping only, for example `config['debug'] == True` or `'password' in config`. Calls, attribute access, imports and any other syntax are rejected and reported as an invalid rule.

Exit codes: 0 when the scan runs and finds nothing, 1 when findings are reported (or an input file is missing), and 2 when a rules file loads no rules, a configuration file cannot be parsed, or a rule is invalid. An empty rules file and an unparseable configuration are errors, never a clean result. The core scan does not need `networkx` or `matplotlib`; those are imported only by the optional graph and visualization features.

## Install
`git clone https://github.com/ShadowStrikeHQ/tm-misconfigurationdetector`

## Usage
`./tm-misconfigurationdetector [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Path to a rules file (YAML or JSON). If omitted, the built-in predefined rules are used.
- `-v`: Enable verbose logging

## License
Copyright (c) ShadowStrikeHQ
