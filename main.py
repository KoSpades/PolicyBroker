from fastapi import FastAPI, HTTPException, Security, Depends, status
from intentObject import Intent
import casbin
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from fastapi.security import (
    OAuth2PasswordBearer,
    SecurityScopes,
)
from pydantic import ValidationError
from fastapi.responses import FileResponse

# Creating the Casbin enforcer based on model.conf and policy.csv
e = casbin.Enforcer("model.conf", "policy.csv")

# Defining some constants here

# The secret key will be used to encode/decode the JWT
# Algorithm is the encoding algorithm for the JWT
# And ACCESS_TOKEN_EXPIRE_MINUTES indicates how long the token will be valid for

SECRET_KEY = "550fc6cbe5ed4d64cc6944dfb222596dc899b8adddc9c611839f31a56c35a7d5"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2

# We now create the oauth2_Scheme.
# Note that currently there are two scopes: "fileA" and "read"

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"fileA": "Trying to access file A.",
            "read": "Performing the read action.",
            "write": "Performing the write action"},
)

# Here we initialize fileA, just as a global variable
fileA_path = "fileA.txt"


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


# Now we define a function that reads file content,
# given a valid access token
async def get_file_content(
    file: str,
    action: str,
    token: str = Depends(oauth2_scheme),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": f"Bearer"},
    )
    # In the following try-except block we verify the token validity
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        intent_subject: str = payload.get("sub")
        if intent_subject is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
    except (JWTError, ValidationError):
        raise credentials_exception
    # In the following blocks we verify all the scopes are satisfied
    if file not in token_scopes or action not in token_scopes:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": f"Bearer"},
        )
    # If at this stage we still have not raised an exception, then everything is good
    # And we can return whatever needs to be returned
    return_file_path = file + ".txt"
    return return_file_path


# Start running the application
app = FastAPI()


# Basic test: get a message from the root
@app.get("/")
async def welcome():
    return {"message": "Welcome to Policy Broker"}


# Clients post to this URL to create the access token
@app.post("/token")
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


# After clients successfully create the token,
# they will use the following method to access any files, either through read or write.
@app.get("/resource")
async def access_file(file_path: str = Depends(get_file_content)):
    return FileResponse(file_path)








