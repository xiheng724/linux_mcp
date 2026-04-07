#!/usr/bin/env python3
"""
Calculate days from today to a given date.
Usage: python3 days_calculator.py YYYY-MM-DD
"""
import sys
from datetime import datetime, date

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 days_calculator.py YYYY-MM-DD")
        sys.exit(1)
    
    target_str = sys.argv[1]
    try:
        target_date = datetime.strptime(target_str, "%Y-%m-%d").date()
    except ValueError:
        print(f"Invalid date format: {target_str}. Please use YYYY-MM-DD.")
        sys.exit(1)
    
    today = date.today()
    delta = target_date - today
    days = delta.days
    
    if days > 0:
        print(f"{days} days from today to {target_str}.")
    elif days < 0:
        print(f"{abs(days)} days have passed since {target_str}.")
    else:
        print(f"Today is {target_str}!")

if __name__ == "__main__":
    main()
