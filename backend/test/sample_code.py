# sample_code.py
def calculate(x, y):
    result = eval(f"{x} + {y}")  # Insecure usage
    temp = 5
    return result

calculate(5, 10)
