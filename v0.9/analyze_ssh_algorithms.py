#!/usr/bin/env python
# -*- coding: utf-8 -*-

def analyze_ssh_supported_algorithms(output):
    supported_algorithms = {}

    sections = output.split('\n\n')
    for section in sections:
        lines = section.strip().split('\n')
        category = lines[0]
        algorithms = [algo.strip() for algo in lines[1:]]

        supported_algorithms[category] = algorithms

    return supported_algorithms

def main():
    # Replace this with the actual output from the vulnerability scan
    vulnerability_output = """
    ... (paste the output here)
    """

    algorithms_info = analyze_ssh_supported_algorithms(vulnerability_output)

    for category, algorithms in algorithms_info.items():
        print('The server supports the following options for {} :'.format(category))
        for algo in algorithms:
            print('  ' + algo)
        print()

if __name__ == '__main__':
    main()
