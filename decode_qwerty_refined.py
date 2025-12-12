#!/usr/bin/env python3
"""
Refined QWERTY keyboard decoding
"""

def qwerty_decode(pos):
    """QWERTY keyboard: top row (1-10), middle (11-19), bottom (20-26)"""
    qwerty_top = "QWERTYUIOP"
    qwerty_mid = "ASDFGHJKL"
    qwerty_bot = "ZXCVBNM"
    
    if 1 <= pos <= 10:
        return qwerty_top[pos - 1]
    elif 11 <= pos <= 19:
        return qwerty_mid[pos - 11]
    elif 20 <= pos <= 26:
        return qwerty_bot[pos - 20]
    return None

def main():
    print("=" * 70)
    print("QWERTY KEYBOARD DECODING")
    print("=" * 70)
    print("\nCipher: 26 9594 - 11 19 8 25 and 24 11 25 11\n")
    
    # Decode main parts
    part1 = qwerty_decode(26)  # M
    part3_letters = [qwerty_decode(11), qwerty_decode(19), 
                     qwerty_decode(8), qwerty_decode(25)]  # A, L, I, N
    part4_letters = [qwerty_decode(24), qwerty_decode(11), 
                     qwerty_decode(25), qwerty_decode(11)]  # B, A, N, A
    
    print(f"26 → {part1}")
    print(f"11 19 8 25 → {''.join(part3_letters)}")
    print(f"24 11 25 11 → {''.join(part4_letters)}")
    
    # Handle 9594
    print("\nHandling 9594:")
    print("Option 1: Split as 9, 5, 9, 4")
    digits_9594 = [9, 5, 9, 4]
    part2_letters = [qwerty_decode(d) for d in digits_9594]
    print(f"  9 5 9 4 → {''.join(part2_letters)}")
    
    print("\nOption 2: Treat as single number (out of range)")
    print("Option 3: Ignore it")
    print("Option 4: Modulo 26")
    mod_9594 = 9594 % 26
    if mod_9594 == 0:
        mod_9594 = 26
    print(f"  9594 % 26 = {mod_9594} → {qwerty_decode(mod_9594)}")
    
    print("\n" + "=" * 70)
    print("POSSIBLE DECODED MESSAGES:")
    print("=" * 70)
    
    # Option 1: With 9594 split
    msg1 = f"{part1} {''.join(part2_letters)} {''.join(part3_letters)} {''.join(part4_letters)}"
    print(f"\n1. With 9594 as 9-5-9-4: {msg1}")
    print(f"   = M {''.join(part2_letters)} {''.join(part3_letters)} {''.join(part4_letters)}")
    
    # Option 2: Ignoring 9594
    msg2 = f"{part1} {''.join(part3_letters)} {''.join(part4_letters)}"
    print(f"\n2. Ignoring 9594: {msg2}")
    print(f"   = M ALIN BANA")
    
    # Option 3: With 9594 modulo
    msg3 = f"{part1} {qwerty_decode(mod_9594)} {''.join(part3_letters)} {''.join(part4_letters)}"
    print(f"\n3. With 9594 modulo 26: {msg3}")
    
    print("\n" + "=" * 70)
    print("TURKISH WORD ANALYSIS:")
    print("=" * 70)
    print("ALIN = 'forehead' or 'take' (imperative plural)")
    print("BANA = 'to me'")
    print("\n'M ALIN BANA' could be:")
    print("  - 'M take to me' (grammatically odd)")
    print("  - 'MALIN BANA' = 'my property to me' (if M+ALIN)")
    print("  - Or maybe M is separate and it's 'ALIN BANA' = 'take to me'")
    
    # Maybe the M and the rest should be combined differently
    print("\n" + "=" * 70)
    print("ALTERNATIVE READINGS:")
    print("=" * 70)
    print(f"Combined: {part1}{''.join(part3_letters)}{''.join(part4_letters)}")
    print(f"  = MALINBANA")
    print(f"\nOr with space: {part1} {''.join(part3_letters)} {''.join(part4_letters)}")
    print(f"  = M ALIN BANA")
    
    # What if 9594 is actually part of the message differently?
    print("\n" + "=" * 70)
    print("FINAL MOST LIKELY:")
    print("=" * 70)
    print("Using QWERTY keyboard positions:")
    print(f"  {msg2}")
    print("\nThis contains Turkish words: ALIN and BANA")

if __name__ == "__main__":
    main()
