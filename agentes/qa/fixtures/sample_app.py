def add(a, b):
    return a + b


def calculate_discount(price, percent):
    if percent < 0 or percent > 100:
        raise ValueError("Invalid percentage")
    return price * (1 - percent / 100)
