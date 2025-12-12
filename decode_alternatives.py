#!/usr/bin/env python3
"""
Trying alternative decoding methods
"""

def english_alphabet(pos):
    if 1 <= pos <= 26:
        return chr(ord('A') + pos - 1)
    return None

def reverse_english(pos):
    if 1 <= pos <= 26:
        return chr(ord('Z') - pos + 1)
    return None

def phone_keypad_decode(numbers):
    """T9 phone keypad: 2=ABC, 3=DEF, 4=GHI, 5=JKL, 6=MNO, 7=PQRS, 8=TUV, 9=WXYZ"""
    keypad = {
        2: 'ABC', 3: 'DEF', 4: 'GHI', 5: 'JKL',
        6: 'MNO', 7: 'PQRS', 8: 'TUV', 9: 'WXYZ'
    }
    result = []
    for num in numbers:
        if num in keypad:
            # Try first letter (most common)
            result.append(keypad[num][0])
        else:
            result.append(f'[{num}]')
    return ''.join(result)

def try_all_methods():
    print("=" * 70)
    print("ALTERNATIVE DECODING METHODS")
    print("=" * 70)
    print("\nCipher: 26 9594 - 11 19 8 25 and 24 11 25 11\n")
    
    # Method 1: English Alphabet
    print("=" * 70)
    print("METHOD 1: English Alphabet (A=1, B=2, ..., Z=26)")
    print("=" * 70)
    print(f"26 → {english_alphabet(26)}")
    print(f"11 19 8 25 → {english_alphabet(11)}{english_alphabet(19)}{english_alphabet(8)}{english_alphabet(25)}")
    print(f"24 11 25 11 → {english_alphabet(24)}{english_alphabet(11)}{english_alphabet(25)}{english_alphabet(11)}")
    print(f"Result: {english_alphabet(26)} {english_alphabet(11)}{english_alphabet(19)}{english_alphabet(8)}{english_alphabet(25)} {english_alphabet(24)}{english_alphabet(11)}{english_alphabet(25)}{english_alphabet(11)}")
    
    # Method 2: Reverse English Alphabet
    print("\n" + "=" * 70)
    print("METHOD 2: Reverse English Alphabet (Z=1, Y=2, ..., A=26)")
    print("=" * 70)
    print(f"26 → {reverse_english(26)}")
    print(f"11 19 8 25 → {reverse_english(11)}{reverse_english(19)}{reverse_english(8)}{reverse_english(25)}")
    print(f"24 11 25 11 → {reverse_english(24)}{reverse_english(11)}{reverse_english(25)}{reverse_english(11)}")
    print(f"Result: {reverse_english(26)} {reverse_english(11)}{reverse_english(19)}{reverse_english(8)}{reverse_english(25)} {reverse_english(24)}{reverse_english(11)}{reverse_english(25)}{reverse_english(11)}")
    
    # Method 3: Phone Keypad (T9) - treating each number as a key
    print("\n" + "=" * 70)
    print("METHOD 3: Phone Keypad (T9) - First letter of each key")
    print("=" * 70)
    # Split 9594 as 9, 5, 9, 4
    digits_9594 = [9, 5, 9, 4]
    part3 = [11, 19, 8, 25]
    part4 = [24, 11, 25, 11]
    
    # For phone keypad, we need single digits 2-9
    # 11, 19, 8, 25 don't map directly - maybe split them?
    print("Note: Phone keypad only has keys 2-9, so 11, 19, 25, 24 need different handling")
    
    # Method 4: Split multi-digit numbers
    print("\n" + "=" * 70)
    print("METHOD 4: Split ALL numbers into single digits")
    print("=" * 70)
    all_digits = [2, 6, 9, 5, 9, 4, 1, 1, 1, 9, 8, 2, 5, 2, 4, 1, 1, 2, 5, 1, 1]
    print(f"All digits: {all_digits}")
    print("English alphabet mapping:")
    eng_result = ''.join([english_alphabet(d) if d <= 26 else f'[{d}]' for d in all_digits])
    print(f"Result: {eng_result}")
    
    # Method 5: Maybe it's coordinates or grid-based
    print("\n" + "=" * 70)
    print("METHOD 5: Grid-based (5x6 or 6x5 grid)")
    print("=" * 70)
    # A 5x6 grid would have 30 positions
    # Row 1: 1-5, Row 2: 6-10, etc.
    def grid_decode_5x6(pos):
        row = (pos - 1) // 5
        col = (pos - 1) % 5
        return f"R{row+1}C{col+1}"
    print("5x6 grid positions:")
    print(f"26 → {grid_decode_5x6(26)}")
    print(f"11 → {grid_decode_5x6(11)}")
    print(f"19 → {grid_decode_5x6(19)}")
    print(f"8 → {grid_decode_5x6(8)}")
    print(f"25 → {grid_decode_5x6(25)}")
    print(f"24 → {grid_decode_5x6(24)}")
    
    # Method 6: Maybe it's reading numbers as words
    print("\n" + "=" * 70)
    print("METHOD 6: Numbers as words (English)")
    print("=" * 70)
    number_words = {
        26: "TWENTYSIX", 11: "ELEVEN", 19: "NINETEEN", 
        8: "EIGHT", 25: "TWENTYFIVE", 24: "TWENTYFOUR"
    }
    print("This would be: TWENTYSIX NINEFIVENINEFOUR ELEVEN NINETEEN EIGHT TWENTYFIVE TWENTYFOUR ELEVEN TWENTYFIVE ELEVEN")
    print("(Doesn't seem right)")
    
    # Method 7: Maybe subtract or add something
    print("\n" + "=" * 70)
    print("METHOD 7: Caesar cipher variations")
    print("=" * 70)
    for shift in [-1, 1, -2, 2]:
        shifted_26 = 26 + shift
        shifted_11 = 11 + shift
        shifted_19 = 19 + shift
        shifted_8 = 8 + shift
        shifted_25 = 25 + shift
        shifted_24 = 24 + shift
        
        if all(1 <= x <= 26 for x in [shifted_26, shifted_11, shifted_19, shifted_8, shifted_25, shifted_24]):
            print(f"\nShift by {shift}:")
            print(f"  {shifted_26} → {english_alphabet(shifted_26)}")
            print(f"  {shifted_11} {shifted_19} {shifted_8} {shifted_25} → {english_alphabet(shifted_11)}{english_alphabet(shifted_19)}{english_alphabet(shifted_8)}{english_alphabet(shifted_25)}")
            print(f"  {shifted_24} {shifted_11} {shifted_25} {shifted_11} → {english_alphabet(shifted_24)}{english_alphabet(shifted_11)}{english_alphabet(shifted_25)}{english_alphabet(shifted_11)}")
    
    # Method 8: Maybe it's a different interpretation of 9594
    print("\n" + "=" * 70)
    print("METHOD 8: Different interpretations of 9594")
    print("=" * 70)
    print("9594 could be:")
    print("  - 95 and 94: {english_alphabet(95%26) if 95%26 != 0 else english_alphabet(26)} {english_alphabet(94%26) if 94%26 != 0 else english_alphabet(26)}")
    print("  - 9, 5, 9, 4: {english_alphabet(9)}{english_alphabet(5)}{english_alphabet(9)}{english_alphabet(4)}")
    print("  - Ignore it completely")
    
    # Method 9: Maybe read it backwards
    print("\n" + "=" * 70)
    print("METHOD 9: Reading the sequence backwards")
    print("=" * 70)
    reverse_seq = [11, 25, 11, 24, 25, 8, 19, 11, 26]
    print(f"Reversed: {reverse_seq}")
    eng_rev = ''.join([english_alphabet(x) for x in reverse_seq if english_alphabet(x)])
    print(f"English: {eng_rev}")
    
    # Method 10: Maybe it's modulo 26
    print("\n" + "=" * 70)
    print("METHOD 10: Modulo 26 (for numbers > 26)")
    print("=" * 70)
    print("9594 % 26 =", 9594 % 26, "→", english_alphabet(9594 % 26))
    print("95 % 26 =", 95 % 26, "→", english_alphabet(95 % 26))
    print("94 % 26 =", 94 % 26, "→", english_alphabet(94 % 26))

if __name__ == "__main__":
    try_all_methods()
