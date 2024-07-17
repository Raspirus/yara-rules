import re
import os

def extract_yara_rules(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    
    # Regular expression to match YARA rules
    rule_pattern = re.compile(r'(rule\s+[\w_]+\s*:\s*.*?\{.*?\n\})', re.DOTALL)
    
    # Extract the rule names and full rule texts
    rule_texts = rule_pattern.finditer(content)
    
    for match in rule_texts:
        rule_text = match.group(0)
        
        # Extract the rule name using another regex
        rule_name_match = re.search(r'rule\s+([\w_]+)\s*:', rule_text)
        if rule_name_match:
            rule_name = rule_name_match.group(1)
            
            # Find the first uppercase part of the rule name that may include numbers
            rule_name_prefix = re.match(r'[A-Z0-9]+', rule_name).group(0)
            
            # Create directory path
            dir_path = rule_name_prefix
            
            # Create directories if they don't exist
            os.makedirs(dir_path, exist_ok=True)
            
            # Create the output file name and path
            output_file_name = f"{rule_name}.yar"
            output_file_path = os.path.join(dir_path, output_file_name)
            
            # Write each rule to a separate file named after the rule
            with open(output_file_path, 'w') as rule_file:
                rule_file.write(rule_text)
            print(f"Rule '{rule_name}' written to '{output_file_path}'.")
        else:
            print("Error: Unable to find rule name.")

if __name__ == "__main__":
    input_file_path = 'yara-rules-core.yar'  # Replace with your input file path
    extract_yara_rules(input_file_path)
