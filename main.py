#!/usr/bin/env python3

import argparse
import ast
import logging
import yaml
import json
import jsonschema
import os
import sys


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class RuleError(Exception):
    """Raised when a rule is invalid or a condition uses a disallowed shape."""


_ALLOWED_COMPARE_OPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)


def _check_node(node, config_data):
    """Interpret one whitelisted AST node against config_data.

    Allowed shapes: literals, the name ``config``, bare names that are keys
    of the config mapping, subscripts on the config mapping only, comparisons
    (==, !=, <, <=, >, >=, in, not in), and boolean and/or/not. Everything
    else, including calls, attribute access, imports and dunder names, raises
    RuleError.
    """
    if isinstance(node, ast.Expression):
        return _check_node(node.body, config_data)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int, float, bool, type(None))):
            return node.value
        raise RuleError(f"Literal of type {type(node.value).__name__} is not allowed in a rule condition.")
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result = True
            for value_node in node.values:
                result = _check_node(value_node, config_data)
                if not result:
                    return result
            return result
        if isinstance(node.op, ast.Or):
            result = False
            for value_node in node.values:
                result = _check_node(value_node, config_data)
                if result:
                    return result
            return result
        raise RuleError("Only 'and' and 'or' boolean operators are allowed in a rule condition.")
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not _check_node(node.operand, config_data)
        if isinstance(node.op, (ast.USub, ast.UAdd)) and isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, (int, float)):
            return -node.operand.value if isinstance(node.op, ast.USub) else node.operand.value
        raise RuleError("Only 'not' (and signed number literals) are allowed as unary operators in a rule condition.")
    if isinstance(node, ast.Compare):
        left = _check_node(node.left, config_data)
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, _ALLOWED_COMPARE_OPS):
                raise RuleError(f"Comparison operator {type(op).__name__} is not allowed in a rule condition.")
            right = _check_node(comparator, config_data)
            try:
                if isinstance(op, ast.Eq):
                    ok = left == right
                elif isinstance(op, ast.NotEq):
                    ok = left != right
                elif isinstance(op, ast.Lt):
                    ok = left < right
                elif isinstance(op, ast.LtE):
                    ok = left <= right
                elif isinstance(op, ast.Gt):
                    ok = left > right
                elif isinstance(op, ast.GtE):
                    ok = left >= right
                elif isinstance(op, ast.In):
                    ok = left in right
                else:
                    ok = left not in right
            except TypeError as e:
                raise RuleError(f"Comparison in rule condition could not be checked: {e}")
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        if node.id == 'config':
            return config_data
        if node.id.startswith('__'):
            raise RuleError(f"Name '{node.id}' is not allowed in a rule condition.")
        if isinstance(config_data, dict) and node.id in config_data:
            return config_data[node.id]
        raise RuleError(f"Name '{node.id}' in a rule condition does not match any field of the configuration.")
    if isinstance(node, ast.Subscript):
        if not (isinstance(node.value, ast.Name) and node.value.id == 'config'):
            raise RuleError("Subscripts are allowed only on the config mapping, for example config['debug'].")
        key_node = node.slice
        if not (isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)):
            raise RuleError("Config subscripts must use a plain string key, for example config['debug'].")
        if isinstance(config_data, dict):
            return config_data.get(key_node.value)
        raise RuleError("The configuration is not a mapping, so config subscripts cannot be checked.")
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_check_node(element, config_data) for element in node.elts]
        if isinstance(node, ast.List):
            return values
        if isinstance(node, ast.Tuple):
            return tuple(values)
        return set(values)
    raise RuleError(f"Syntax of type {type(node).__name__} is not allowed in a rule condition.")


def check_condition(condition, config_data):
    """Check a custom rule condition string against config_data.

    Returns a boolean. Raises RuleError for any condition outside the
    whitelisted shapes; nothing in the condition is run as code.
    """
    if not isinstance(condition, str) or not condition.strip():
        raise RuleError("Custom rule condition must be a non-empty string.")
    try:
        module_tree = ast.parse(condition)
    except SyntaxError as e:
        raise RuleError(f"Custom rule condition does not parse: {e}")
    if len(module_tree.body) != 1 or not isinstance(module_tree.body[0], ast.Expr):
        raise RuleError("Custom rule condition must be a single expression.")
    return bool(_check_node(module_tree.body[0].value, config_data))


DEFAULT_RULES = {
    "no_debug_enabled": {
        "type": "custom",
        "condition": "config['debug'] == True",
        "severity": "high",
        "description": "Debug mode is enabled (debug is true).",
    },
    "no_plaintext_password_key": {
        "type": "custom",
        "condition": "'password' in config",
        "severity": "high",
        "description": "A plaintext password key is present in the configuration.",
    },
    "tls_not_disabled": {
        "type": "custom",
        "condition": "config['tls_enabled'] == False",
        "severity": "high",
        "description": "TLS is explicitly disabled (tls_enabled is false).",
    },
    "no_wildcard_bind": {
        "type": "custom",
        "condition": "config['bind_address'] == '0.0.0.0'",
        "severity": "medium",
        "description": "The service binds to all interfaces (bind_address is 0.0.0.0).",
    },
}


class MisconfigurationDetector:
    """
    Scans configuration files against predefined security best practices to identify
    common misconfigurations and vulnerabilities.
    """

    def __init__(self, rules_file=None):
        if rules_file:
            self.rules = self._load_rules(rules_file)
            if not isinstance(self.rules, dict) or not self.rules:
                raise RuleError(f"Rules file loaded no rules: {rules_file}. An empty rules file is an error, not a clean scan.")
        else:
            self.rules = dict(DEFAULT_RULES)
        self._graph = None

    @property
    def G(self):
        if self._graph is None:
            import networkx as nx
            self._graph = nx.DiGraph()
        return self._graph

    @G.setter
    def G(self, value):
        self._graph = value

    def _load_rules(self, rules_file):
        try:
            with open(rules_file, 'r') as f:
                lower = rules_file.lower()
                if lower.endswith('.yaml') or lower.endswith('.yml'):
                    return yaml.safe_load(f)
                elif lower.endswith('.json'):
                    return json.load(f)
                else:
                    raise RuleError(f"Unsupported file format for rules file: {rules_file}")
        except RuleError:
            raise
        except FileNotFoundError:
            raise RuleError(f"Rules file not found: {rules_file}")
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise RuleError(f"Error parsing rules file {rules_file}: {e}")
        except Exception as e:
            raise RuleError(f"Unexpected error loading rules from {rules_file}: {e}")

    def scan_config(self, config_file):
        findings = []
        config_data = self._load_config(config_file)
        if config_data is None:
            raise RuleError(f"Configuration file could not be loaded or parsed: {config_file}")
        if not self.rules:
            raise RuleError("No rules are loaded, so no scan can be performed.")
        for rule_name, rule_details in self.rules.items():
            if not isinstance(rule_details, dict) or 'type' not in rule_details:
                raise RuleError(f"Rule '{rule_name}' is missing its 'type' attribute.")
            rule_type = rule_details['type']
            if rule_type == 'jsonschema':
                if 'schema' not in rule_details:
                    raise RuleError(f"Rule '{rule_name}' of type 'jsonschema' is missing its 'schema' attribute.")
                try:
                    jsonschema.validate(instance=config_data, schema=rule_details['schema'])
                except jsonschema.ValidationError as e:
                    findings.append({
                        'description': rule_details.get('description', f"Validation failed for schema '{rule_name}': {e.message}"),
                        'severity': rule_details.get('severity', 'medium'),
                        'path': e.path
                    })
            elif rule_type == 'custom':
                if 'condition' not in rule_details:
                    raise RuleError(f"Rule '{rule_name}' of type 'custom' is missing its 'condition' attribute.")
                condition = rule_details['condition']
                try:
                    matched = check_condition(condition, config_data)
                except RuleError:
                    raise
                except Exception as e:
                    raise RuleError(f"Rule '{rule_name}' has an invalid condition '{condition}': {e}")
                if matched:
                    findings.append({
                        'description': rule_details.get('description', f"Custom condition '{condition}' matched."),
                        'severity': rule_details.get('severity', 'medium')
                    })
            else:
                raise RuleError(f"Unknown rule type '{rule_type}' for rule '{rule_name}'.")
        return findings

    def _load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                lower = config_file.lower()
                if lower.endswith('.yaml') or lower.endswith('.yml'):
                    return yaml.safe_load(f)
                elif lower.endswith('.json'):
                    return json.load(f)
                else:
                    logging.error(f"Unsupported file format for config file: {config_file}")
                    return None
        except FileNotFoundError:
            logging.error(f"Config file not found: {config_file}")
            return None
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML config file: {e}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing JSON config file: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error loading config: {e}")
            return None

    def add_node(self, node_id, attributes=None):
        """Adds a node to the threat model graph. Needs networkx, imported on use."""
        try:
            self.G.add_node(node_id, **(attributes or {}))
            logging.info(f"Added node: {node_id}")
        except Exception as e:
            logging.error(f"Error adding node {node_id}: {e}")

    def add_edge(self, from_node, to_node, attributes=None):
        """Adds an edge to the threat model graph. Needs networkx, imported on use."""
        try:
            self.G.add_edge(from_node, to_node, **(attributes or {}))
            logging.info(f"Added edge: {from_node} -> {to_node}")
        except Exception as e:
            logging.error(f"Error adding edge {from_node} -> {to_node}: {e}")

    def visualize_graph(self, output_file="threat_model.png"):
        """Visualizes the threat model graph. Needs networkx and matplotlib, imported on use."""
        import networkx as nx
        import matplotlib.pyplot as plt
        try:
            pos = nx.spring_layout(self.G)
            nx.draw(self.G, pos, with_labels=True, node_size=1500, node_color="skyblue", font_size=10, font_weight="bold")
            plt.savefig(output_file)
            logging.info(f"Threat model graph saved to: {output_file}")
            plt.clf()
        except Exception as e:
            logging.error(f"Error visualizing graph: {e}")


def setup_argparse():
    parser = argparse.ArgumentParser(description="Scans configuration files for security misconfigurations.")
    parser.add_argument("config_file", help="Path to the configuration file to scan.")
    parser.add_argument("-r", "--rules_file", help="Path to the rules file (YAML or JSON). If omitted, the built-in predefined rules are used.", required=False, default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    threat_group = parser.add_argument_group("Threat Modeling")
    threat_group.add_argument("--add_node", nargs='+', help="Add a node to the threat model graph.  Usage: --add_node node_id [attribute1=value1 attribute2=value2 ...]")
    threat_group.add_argument("--add_edge", nargs=2, help="Add an edge to the threat model graph. Usage: --add_edge from_node to_node")
    threat_group.add_argument("--visualize", action="store_true", help="Visualize the threat model graph and save it to a file (threat_model.png). Needs networkx and matplotlib.")
    return parser


def main():
    parser = setup_argparse()
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")
    if not os.path.exists(args.config_file):
        logging.error(f"Config file not found: {args.config_file}")
        sys.exit(1)
    if args.rules_file and not os.path.exists(args.rules_file):
        logging.error(f"Rules file not found: {args.rules_file}")
        sys.exit(1)
    try:
        detector = MisconfigurationDetector(rules_file=args.rules_file)
    except RuleError as e:
        logging.error(str(e))
        sys.exit(2)
    if args.add_node:
        node_id = args.add_node[0]
        attributes = {}
        for item in args.add_node[1:]:
            if "=" not in item:
                logging.error(f"Invalid attribute format: {item}. Use key=value.")
                sys.exit(1)
            key, value = item.split("=", 1)
            attributes[key] = value
        detector.add_node(node_id, attributes)
    if args.add_edge:
        detector.add_edge(args.add_edge[0], args.add_edge[1])
    if args.visualize:
        detector.visualize_graph()
    try:
        findings = detector.scan_config(args.config_file)
    except RuleError as e:
        logging.error(str(e))
        sys.exit(2)
    if findings:
        print("Findings:")
        for finding in findings:
            print(f"  - Severity: {finding['severity']}")
            print(f"    Description: {finding['description']}")
            if 'path' in finding:
                print(f"    Path: {list(finding['path'])}")
        sys.exit(1)
    else:
        print("No misconfigurations found.")


if __name__ == "__main__":
    main()
