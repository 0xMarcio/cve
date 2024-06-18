import sys

if len(sys.argv) < 2:
    print("Usage: python3 script.py <filename>")
    sys.exit(1)

filename = sys.argv[1]
lines_seen = set()

with open(filename, 'r') as file:
    for line in file:
        if line.startswith('- '):
            if line not in lines_seen:
                print(line, end='')
                lines_seen.add(line)
        else:
            print(line, end='')
