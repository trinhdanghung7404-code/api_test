from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jwt import ExpiredSignatureError, InvalidTokenError
import jwt
from datetime import datetime, timedelta

app = FastAPI()
SECRET_KEY = "secret123"
security = HTTPBearer()

users = {
    "user1": {"password": "123", "role": "user"},
    "admin": {"password": "admin", "role": "admin"}
}

items = []

class Login(BaseModel):
    username: str
    password: str

class Item(BaseModel):
    name: str

def create_token(username, role):
    return jwt.encode({
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(seconds=60)
    }, SECRET_KEY, algorithm="HS256")

def get_user(cred: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(cred.credentials, SECRET_KEY, algorithms=["HS256"])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.get("/items")
def get_items():
    return items

@app.get("/items/{i}")
def get_item(i: int, user=Depends(get_user)):
    if i >= len(items):
        raise HTTPException(status_code=404, detail="Item not found")

    item = items[i]

    if item["owner"] != user["sub"]:
        raise HTTPException(status_code=403, detail="Not your item")

    return item

@app.post("/login")
def login(data: Login):
    u = users.get(data.username)
    if not u or u["password"] != data.password:
        raise HTTPException(status_code=401)
    return {"token": create_token(data.username, u["role"])}

@app.get("/profile")
def profile(user=Depends(get_user)):
    return user

@app.post("/items")
def add(item: Item, user=Depends(get_user)):
    items.append({"name": item.name, "owner": user["sub"]})
    return items[-1]

@app.delete("/items/{i}")
def delete(i: int, user=Depends(get_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)
    return items.pop(i)