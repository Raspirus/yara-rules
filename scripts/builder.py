import yara_x
import os

# A script to compile all the Yara rules into a single binary.
# It does this by iterating trough each rule, reading its content and passing it to the YaraX compiler
# The compiler then collects them all and finally compiles them altogether into a single binary file
# The binary file is then saved in the same directory as the script was executed

compiler = yara_x.Compiler()

error_rules = []
number_of_rules = 0

# Iterate through the rules folder and retrieve each yar file in the folder and subfolders
rules_folder = 'rules'
for root, dirs, files in os.walk(rules_folder):
    for file in files:
        if file.endswith('.yar'):
            # Get the content of the file as string
            with open(os.path.join(root, file), 'r') as rule_file:
                content = rule_file.readlines()
                # Replace lines starting with include "..." to start with import "..." instead
                # This is because YaraX does not support include statements
                content = [line.replace('include "', 'import "') for line in content]
                # Add the rule to the compiler
                try:
                    compiler.add_source(''.join(content))
                    number_of_rules += 1
                except Exception as e:
                    error_rules.append(file)
                    print(f'Error compiling {file}: {e}')

# Print the rules that failed to compile
if error_rules:
    print("--------------------")
    print('The following rules failed to compile:')
    for rule in error_rules:
        print(rule)

# Compile the rules
rules = compiler.build()

# Save the compiled rules into a binary file
with open('rulepirus.yarac', 'wb') as write_file:
    rules.serialize_into(write_file)

# Print the number of rules compiled and the number of rules that failed to compile
print(f'Compiled {number_of_rules} rules')
print(f'Failed to compile {len(error_rules)} rules')
