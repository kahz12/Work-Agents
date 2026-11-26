def sumar(a, b):
    return a + b


def calcular_descuento(precio, porcentaje):
    if porcentaje < 0 or porcentaje > 100:
        raise ValueError("Porcentaje inválido")
    return precio * (1 - porcentaje / 100)
