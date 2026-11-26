def get_users():
    """Retorna usuarios."""
    return []


def post_create_user(name: str, age: int = 18):
    """Crea usuario."""
    return {"name": name, "age": age}


def put_update_item(item_id: int, title: str):
    """Actualiza item."""
    return {"id": item_id, "title": title}


def delete_user(uid: int):
    """Elimina usuario."""
    return True
