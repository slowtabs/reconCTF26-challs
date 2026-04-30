#!/usr/bin/env python3
import sys
import os

# Read dynamic flag from environment or fallback
FLAG = os.environ.get('FLAG', open(os.path.join(os.path.dirname(__file__), 'flag.txt')).read().strip() if os.path.exists(os.path.join(os.path.dirname(__file__), 'flag.txt')) else 'recon{test_flag_local}')

class LemonadeShop:
    INT32_MIN = -2147483648
    INT32_MAX = 2147483647
    
    def __init__(self):
        self.money = 10
        self.inventory = {
            "strawberry": 0,
            "watermelon": 0,
            "classic": 0,
            "mango": 0,
        }
        self.prices = {
            "strawberry": 5,
            "watermelon": 7,
            "classic": 3,
            "mango": 9,
        }
        self.premium_cost = 100
        self.items_list = list(self.prices.keys())

    def wrap_int32(self, value):
        """Simulate 32-bit signed integer overflow"""
        if value > self.INT32_MAX:
            value = self.INT32_MIN + (value - self.INT32_MAX - 1)
        elif value < self.INT32_MIN:
            value = self.INT32_MAX + (value - self.INT32_MIN + 1)
        return value

    def display_menu(self):
        print("\n=== Not So OWASP Juice Shop ===")
        print(f"Money: ${self.money}")
        print("1. Strawberry - $5")
        print("2. Watermelon - $7")
        print("3. Classic - $3")
        print("4. Mango - $9")
        print("5. Buy Flag - $100")
        print("0. Quit")

    def buy_item(self, choice):
        item = self.items_list[choice - 1]
        try:
            quantity = int(input(f"Quantity: "))
        except ValueError:
            print("Invalid input")
            return
        
        if quantity <= 0:
            print("Invalid quantity")
            return
        
        cost = self.prices[item] * quantity
        
        self.money -= cost
        self.money = self.wrap_int32(self.money)
        self.inventory[item] += quantity
        print(f"OK")

    def buy_premium(self):
        if self.money >= self.premium_cost:
            print(f"Flag: {FLAG}")
            return True
        else:
            print(f"Need ${self.premium_cost - self.money} more")
        return False

    def run(self):
        while True:
            self.display_menu()
            choice = input("> ").strip()
            
            if choice == '0':
                sys.exit(0)
            elif choice == '5':
                if self.buy_premium():
                    sys.exit(0)
            elif choice in ['1', '2', '3', '4']:
                self.buy_item(int(choice))
            else:
                print("Invalid")


if __name__ == "__main__":
    shop = LemonadeShop()
    shop.run()
