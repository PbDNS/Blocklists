#!/usr/bin/env python3

def main():
    input_file = "blocklist.txt"
    output_file = "AdguardBaseLight.txt"

    with open(input_file, "r", encoding="utf-8") as fin, \
         open(output_file, "w", encoding="utf-8") as fout:
        for line in fin:
            stripped = line.strip()
            if not stripped:
                continue  # Ignore lignes vides
            if stripped.startswith("!"):
                continue  # Ignore commentaires
            if stripped.startswith("||"):
                continue  # Ignore lignes commençant par ||
            fout.write(line)

if __name__ == "__main__":
    main()
