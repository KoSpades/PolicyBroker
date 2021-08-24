from fastapi import FastAPI, HTTPException
from intentObject import Intent
import casbin
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt

# Creating the Casbin enforcer based on model.conf and policy.csv
e = casbin.Enforcer("model.conf", "policy.csv")

# Defining some constants here
SECRET_KEY = "550fc6cbe5ed4d64cc6944dfb222596dc899b8adddc9c611839f31a56c35a7d5"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Now we write a function to check if the intent matches a policy
# using Casbin
def check_intent(intent: Intent):
    return e.enforce(intent.subject, intent.object, intent.action)


# Now we define a function that generates the access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Start running the application
app = FastAPI()


@app.get("/")
async def welcome():
    return {"message": "Welcome to Policy Broker"}


@app.post("/check")
async def receive_intent(intent: Intent):
    result = check_intent(intent)
    # Now result stores the result of the Casbin check.
    # If it passes, we should now generate a token
    if not result:
        raise HTTPException(status_code=400, detail="Intent matches no policy")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    valid_scopes = [intent.object, intent.action]
    access_token = create_access_token(
        data={"sub": intent.subject, "scopes": valid_scopes},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}





