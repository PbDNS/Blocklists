#!/usr/bin/env python3

def main():
    input_file = "blocklist.txt"
    output_file = "AdguardBaseLight.txt"

    with open(input_file, "r", encoding="utf-8") as fin, \
         open(output_file, "w", encoding="utf-8") as fout:
        for line in fin:
            content = line.lstrip()  # conserve \n en fin de ligne
            if not content.strip():
                continue  # ligne vide
            if content.startswith("!"):
                continue  # commentaire
            if content.startswith("||"):
                continue  # ligne à filtrer
            fout.write(line)  # on écrit la ligne originale avec \n intact

if __name__ == "__main__":
    main()
