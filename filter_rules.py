import re

def filter_rules(input_file, output_file):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    filtered_lines = []
    for line in lines:
        # Supprimer les lignes de commentaires
        if line.startswith('!'):
            continue
        # Supprimer les lignes contenant des filtres spécifiques
        if re.match(r'^\|\|www\.[a-zA-Z0-9.-]+\.com\^$', line):
            continue
        filtered_lines.append(line)

    with open(output_file, 'w') as f:
        f.writelines(filtered_lines)

if __name__ == "__main__":
    filter_rules('filter.txt', 'Cosmetic-AdGuardBase.txt')
