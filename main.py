#!/usr/bin/env python3

import argparse
import logging
import yaml
import json
import jsonschema
import os
import sys
import networkx as nx
import matplotlib.pyplot as plt


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MisconfigurationDetector:
    """
    Scans configuration files against predefined security best practices to identify
    common misconfigurations and vulnerabilities.
    """

    def __init__(self, rules_file=None):
        """
        Initializes the MisconfigurationDetector with optional rules file.
        """
        self.rules = self._load_rules(rules_file) if rules_file else {}
        self.G = nx.DiGraph()  # Graph for threat modeling

    def _load_rules(self, rules_file):
        """
        Loads rules from a YAML or JSON file.

        Args:
            rules_file (str): Path to the rules file.

        Returns:
            dict: Loaded rules.  Returns an empty dictionary on error.
        """
        try:
            with open(rules_file, 'r') as f:
                if rules_file.endswith('.yaml') or rules_file.endswith('.yml'):
                    return yaml.safe_load(f)
                elif rules_file.endswith('.json'):
                    return json.load(f)
                else:
                    logging.error(f"Unsupported file format for rules file: {rules_file}")
                    return {}
        except FileNotFoundError:
            logging.error(f"Rules file not found: {rules_file}")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML rules file: {e}")
            return {}
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing JSON rules file: {e}")
            return {}
        except Exception as e:
            logging.error(f"Unexpected error loading rules: {e}")
            return {}

    def scan_config(self, config_file):
        """
        Scans a configuration file and reports any misconfigurations based on defined rules.

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            list: A list of findings, each with a description and severity.
        """
        findings = []
        config_data = self._load_config(config_file)

        if not config_data:
            return findings # Return empty findings list if loading failed.

        for rule_name, rule_details in self.rules.items():
            try:
                if 'type' not in rule_details:
                    logging.warning(f"Rule '{rule_name}' missing 'type' attribute. Skipping.")
                    continue

                rule_type = rule_details['type']

                if rule_type == 'jsonschema':
                    if 'schema' not in rule_details:
                        logging.warning(f"Rule '{rule_name}' of type 'jsonschema' missing 'schema' attribute. Skipping.")
                        continue
                    try:
                        jsonschema.validate(instance=config_data, schema=rule_details['schema'])
                    except jsonschema.ValidationError as e:
                        # Validation failed, meaning a misconfiguration was found.
                        finding = {
                            'description': rule_details.get('description', f"Validation failed for schema '{rule_name}': {e.message}"),
                            'severity': rule_details.get('severity', 'medium'),
                            'path': e.path
                        }
                        findings.append(finding)

                elif rule_type == 'custom':
                    if 'condition' not in rule_details:
                        logging.warning(f"Rule '{rule_name}' of type 'custom' missing 'condition' attribute. Skipping.")
                        continue

                    # Evaluate the custom condition (simplified example).
                    condition = rule_details['condition']
                    try:
                        if eval(condition, {}, {'config': config_data}):  # WARNING: Use eval carefully!  Prefer safer alternatives.
                            finding = {
                                'description': rule_details.get('description', f"Custom condition '{condition}' failed."),
                                'severity': rule_details.get('severity', 'medium')
                            }
                            findings.append(finding)
                    except Exception as e:
                        logging.error(f"Error evaluating custom condition '{condition}': {e}")

                else:
                    logging.warning(f"Unknown rule type '{rule_type}' for rule '{rule_name}'. Skipping.")

            except Exception as e:
                logging.error(f"Error processing rule '{rule_name}': {e}")

        return findings

    def _load_config(self, config_file):
        """
        Loads a configuration file (YAML or JSON).

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            dict: Loaded configuration data, or None if an error occurred.
        """
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f)
                elif config_file.endswith('.json'):
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
        """Adds a node to the threat model graph."""
        try:
            self.G.add_node(node_id, **(attributes or {}))
            logging.info(f"Added node: {node_id}")
        except Exception as e:
            logging.error(f"Error adding node {node_id}: {e}")

    def add_edge(self, from_node, to_node, attributes=None):
        """Adds an edge to the threat model graph."""
        try:
            self.G.add_edge(from_node, to_node, **(attributes or {}))
            logging.info(f"Added edge: {from_node} -> {to_node}")
        except Exception as e:
            logging.error(f"Error adding edge {from_node} -> {to_node}: {e}")

    def visualize_graph(self, output_file="threat_model.png"):
        """Visualizes the threat model graph and saves it to a file."""
        try:
            pos = nx.spring_layout(self.G)  # Layout algorithm
            nx.draw(self.G, pos, with_labels=True, node_size=1500, node_color="skyblue", font_size=10, font_weight="bold")
            plt.savefig(output_file)
            logging.info(f"Threat model graph saved to: {output_file}")
            plt.clf() # Clear the plot to avoid overlapping plots in future calls
        except Exception as e:
            logging.error(f"Error visualizing graph: {e}")

def setup_argparse():
    """Sets up the command-line argument parser."""
    parser = argparse.ArgumentParser(description="Scans configuration files for security misconfigurations.")
    parser.add_argument("config_file", help="Path to the configuration file to scan.")
    parser.add_argument("-r", "--rules_file", help="Path to the rules file (YAML or JSON).", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")

    # Threat modeling arguments
    threat_group = parser.add_argument_group("Threat Modeling")
    threat_group.add_argument("--add_node", nargs='+', help="Add a node to the threat model graph.  Usage: --add_node node_id [attribute1=value1 attribute2=value2 ...]")
    threat_group.add_argument("--add_edge", nargs=2, help="Add an edge to the threat model graph. Usage: --add_edge from_node to_node")
    threat_group.add_argument("--visualize", action="store_true", help="Visualize the threat model graph and save it to a file (threat_model.png).")

    return parser

def main():
    """Main function to parse arguments, run the scan, and output results."""
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    # Input validation
    if not os.path.exists(args.config_file):
        logging.error(f"Config file not found: {args.config_file}")
        sys.exit(1)

    if not os.path.exists(args.rules_file):
        logging.error(f"Rules file not found: {args.rules_file}")
        sys.exit(1)


    detector = MisconfigurationDetector(rules_file=args.rules_file)

    # Threat Modeling Operations
    if args.add_node:
        node_id = args.add_node[0]
        attributes = {}
        for i in range(1, len(args.add_node)):
            try:
                key, value = args.add_node[i].split("=")
                attributes[key] = value
            except ValueError:
                logging.error(f"Invalid attribute format: {args.add_node[i]}. Use key=value.")
                sys.exit(1)
        detector.add_node(node_id, attributes)

    if args.add_edge:
        detector.add_edge(args.add_edge[0], args.add_edge[1])

    if args.visualize:
        detector.visualize_graph()

    # Configuration Scanning
    findings = detector.scan_config(args.config_file)

    if findings:
        print("Findings:")
        for finding in findings:
            print(f"  - Severity: {finding['severity']}")
            print(f"    Description: {finding['description']}")
            if 'path' in finding:
                print(f"    Path: {finding['path']}")
    else:
        print("No misconfigurations found.")


if __name__ == "__main__":
    main()