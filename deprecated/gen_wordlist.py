import itertools
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="High-Speed Combinatorial Wordlist Generator")
    parser.add_argument("--chars", required=True, help="Character set, e.g., abc01XYZ")
    parser.add_argument("--minlen", type=int, default=4, help="Minimum password length")
    parser.add_argument("--maxlen", type=int, default=8, help="Maximum password length")
    parser.add_argument("--output", default="rockyou.txt", help="Output file path (default: rockyou.txt)")
    
    args = parser.parse_args()
    
    char_set = list(args.chars)
    
    print(f"[+] Generating combinations for character set: {''.join(char_set)}")
    print(f"[+] Length boundaries: {args.minlen} to {args.maxlen}")
    print(f"[+] Output target: {args.output}")
    print("[+] Writing to disk... Please wait...")

    try:
        # Open with a large 16MB buffer to minimize disk I/O slowing down generation
        with open(args.output, "w", encoding="utf-8", buffering=16 * 1024 * 1024) as f:
            total_generated = 0
            
            for length in range(args.minlen, args.maxlen + 1):
                # itertools.product handles the math efficiently in C-level memory
                for combo in itertools.product(char_set, repeat=length):
                    f.write(''.join(combo) + '\n')
                    total_generated += 1
                    
                    # Periodic console updates
                    if total_generated % 5000000 == 0:
                        print(f"    -> Written {total_generated:,} words so far...", end="\r")
                        
        print(f"\n[+] Success! Complete wordlist saved. Total words: {total_generated:,}")
        
    except KeyboardInterrupt:
        print("\n[-] Process aborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Critical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
